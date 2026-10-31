use crate::{
    model::{Applicability, Claim, Evidence, EvidenceKind, Instance},
    sources::Intelligence,
};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
struct Csaf {
    document: CsafDocument,
    product_tree: Option<ProductTree>,
    #[serde(default)]
    vulnerabilities: Vec<CsafVulnerability>,
}
#[derive(Deserialize)]
struct CsafDocument {
    csaf_version: String,
}
#[derive(Deserialize)]
struct ProductTree {
    #[serde(default)]
    full_product_names: Vec<Product>,
    #[serde(default)]
    branches: Vec<Branch>,
}
#[derive(Deserialize)]
struct Branch {
    product: Option<Product>,
    #[serde(default)]
    branches: Vec<Branch>,
}
#[derive(Deserialize)]
struct Product {
    product_id: String,
    product_identification_helper: Option<ProductHelper>,
}
#[derive(Deserialize)]
struct ProductHelper {
    purl: Option<String>,
    cpe: Option<String>,
}
#[derive(Deserialize)]
struct CsafVulnerability {
    cve: Option<String>,
    title: Option<String>,
    product_status: Option<ProductStatus>,
}
#[derive(Deserialize)]
struct ProductStatus {
    #[serde(default)]
    known_affected: Vec<String>,
    #[serde(default)]
    known_not_affected: Vec<String>,
    #[serde(default)]
    fixed: Vec<String>,
    #[serde(default)]
    under_investigation: Vec<String>,
}
#[derive(Deserialize)]
struct OpenVex {
    #[serde(rename = "@context")]
    context: String,
    statements: Vec<VexStatement>,
}
#[derive(Deserialize)]
struct VexStatement {
    vulnerability: VexVulnerability,
    products: Vec<VexProduct>,
    status: String,
    justification: Option<String>,
    impact_statement: Option<String>,
}
#[derive(Deserialize)]
struct VexVulnerability {
    name: Option<String>,
    #[serde(rename = "@id")]
    id: Option<String>,
}
#[derive(Deserialize)]
struct VexProduct {
    #[serde(rename = "@id")]
    id: String,
    identifiers: Option<VexIdentifiers>,
}
#[derive(Deserialize)]
struct VexIdentifiers {
    purl: Option<String>,
}
fn product_matches(helper: &ProductHelper, instance: &Instance) -> Result<bool> {
    let Some(version) = &instance.resolved_version else {
        return Ok(false);
    };
    if let (Some(purl), Some(identity)) = (&helper.purl, &instance.purl) {
        let parsed: packageurl::PackageUrl<'_> = purl.parse()?;
        if parsed.version() != Some(version) {
            return Ok(false);
        }
        let expected: packageurl::PackageUrl<'_> = identity.parse()?;
        return Ok(parsed.ty() == expected.ty()
            && parsed.namespace() == expected.namespace()
            && parsed.name() == expected.name()
            && parsed.qualifiers() == expected.qualifiers());
    }
    if let (Some(cpe), Some(product)) = (&helper.cpe, &instance.cpe_product) {
        let exact = format!("{product}:{version}:");
        return Ok(cpe.starts_with(&exact)
            && cpe
                .split(':')
                .skip(6)
                .all(|part| part == "*" || part == "-"));
    }
    Ok(false)
}
fn claim(
    id: String,
    summary: String,
    applicability: Applicability,
    instance: &Instance,
    evidence: &Evidence,
) -> Claim {
    let mut evidence = evidence.clone();
    if applicability == Applicability::NotAffected {
        evidence.kind = EvidenceKind::NonApplicability;
    }
    Claim {
        id,
        source: "vendor".into(),
        aliases: Vec::new(),
        instance_id: instance.id.clone(),
        summary,
        applicability,
        evidence,
        known_exploited: false,
    }
}
pub fn parse_csaf(
    bytes: &[u8],
    instances: &[&Instance],
    evidence: &Evidence,
) -> Result<Vec<Claim>> {
    let csaf: Csaf = serde_json::from_slice(bytes)?;
    if csaf.document.csaf_version != "2.0" {
        bail!("CSAF version unsupported (2.0 only)");
    }
    let tree = csaf.product_tree.context("CSAF product tree missing")?;
    let mut products: HashMap<String, ProductHelper> = HashMap::new();
    fn insert(product: Product, products: &mut HashMap<String, ProductHelper>) {
        if let Some(helper) = product.product_identification_helper {
            products.insert(product.product_id, helper);
        }
    }
    fn visit(
        branches: Vec<Branch>,
        products: &mut HashMap<String, ProductHelper>,
        depth: usize,
    ) -> Result<()> {
        if depth > 32 {
            bail!("CSAF tree nesting exceeds limit");
        }
        for branch in branches {
            if let Some(product) = branch.product {
                insert(product, products);
            }
            visit(branch.branches, products, depth + 1)?;
        }
        Ok(())
    }
    for product in tree.full_product_names {
        insert(product, &mut products);
    }
    visit(tree.branches, &mut products, 0)?;
    let mut claims = Vec::new();
    for vulnerability in csaf.vulnerabilities {
        let Some(id) = vulnerability.cve else {
            continue;
        };
        let Some(status) = vulnerability.product_status else {
            continue;
        };
        for (identifiers, applicability) in [
            (status.known_affected, Applicability::Affected),
            (status.known_not_affected, Applicability::NotAffected),
            (status.fixed, Applicability::NotAffected),
            (status.under_investigation, Applicability::Possible),
        ] {
            for identifier in identifiers {
                let Some(helper) = products.get(&identifier) else {
                    continue;
                };
                for instance in instances {
                    if product_matches(helper, instance)? {
                        claims.push(claim(
                            id.clone(),
                            vulnerability.title.clone().unwrap_or_else(|| id.clone()),
                            applicability,
                            instance,
                            evidence,
                        ));
                    }
                }
            }
        }
    }
    Ok(claims)
}
pub fn parse_openvex(
    bytes: &[u8],
    instances: &[&Instance],
    evidence: &Evidence,
) -> Result<Vec<Claim>> {
    let vex: OpenVex = serde_json::from_slice(bytes)?;
    if ![
        "https://openvex.dev/ns/v0.2.0",
        "https://openvex.dev/ns/v0.2.0/",
    ]
    .contains(&vex.context.as_str())
    {
        bail!("only OpenVEX 0.2.0 is supported; JSON-LD contexts are never fetched");
    }
    let mut claims = Vec::new();
    for statement in vex.statements {
        let id = statement
            .vulnerability
            .name
            .or(statement.vulnerability.id)
            .context("VEX vulnerability ID missing")?;
        let applicability = match statement.status.as_str() {
            "affected" => Applicability::Affected,
            "not_affected" | "fixed" => Applicability::NotAffected,
            "under_investigation" => Applicability::Possible,
            _ => bail!("unknown VEX status"),
        };
        if applicability == Applicability::NotAffected
            && statement.justification.is_none()
            && statement.impact_statement.is_none()
        {
            bail!("VEX not_affected requires positive justification/impact_statement");
        }
        for product in statement.products {
            let purl = product
                .identifiers
                .and_then(|identifiers| identifiers.purl)
                .unwrap_or(product.id);
            let helper = ProductHelper {
                purl: Some(purl),
                cpe: None,
            };
            for instance in instances {
                if product_matches(&helper, instance)? {
                    claims.push(claim(
                        id.clone(),
                        statement
                            .impact_statement
                            .clone()
                            .unwrap_or_else(|| id.clone()),
                        applicability,
                        instance,
                        evidence,
                    ));
                }
            }
        }
    }
    Ok(claims)
}
pub fn feeds(
    profile: &crate::profile::Profile,
    instances: &[Instance],
    http: &mut crate::network::Http<'_>,
) -> Intelligence {
    use crate::model::{Coverage, CoverageState};
    use crate::profile::FeedKind;
    let mut intelligence = Intelligence::default();
    for component in &profile.components {
        let scope: Vec<&Instance> = instances
            .iter()
            .filter(|instance| {
                instance.reference == component.reference
                    && instance.requested_version == component.version
            })
            .collect();
        for feed in &component.feeds {
            if matches!(feed.kind, FeedKind::Rss | FeedKind::Atom) {
                intelligence.coverage.push(Coverage::new(
                    "vendor",
                    &component.reference,
                    CoverageState::Unsupported,
                    "RSS/Atom not parsed; use agent research",
                ));
                continue;
            }
            let result = http.get(&feed.url).and_then(|response| {
                let evidence = http.store.record_evidence(
                    &response.body,
                    "configured_vendor",
                    Some(response.url),
                    EvidenceKind::Advisory,
                )?;
                match feed.kind {
                    FeedKind::Csaf => parse_csaf(&response.body, &scope, &evidence),
                    FeedKind::Vex => parse_openvex(&response.body, &scope, &evidence),
                    _ => bail!("unsupported feed"),
                }
            });
            match result {
                Ok(claims) => {
                    intelligence.claims.extend(claims);
                    intelligence.coverage.push(Coverage::new("vendor",&component.reference,CoverageState::Partial,"structured CSAF 2.0/OpenVEX 0.2.0 parsed; exact PURL/CPE only, product relationships/ranges and signatures not evaluated"));
                }
                Err(error) => intelligence.coverage.push(Coverage::new(
                    "vendor",
                    &component.reference,
                    CoverageState::Partial,
                    error.to_string(),
                )),
            }
        }
    }
    intelligence
}
