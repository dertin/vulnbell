use super::*;

fn pom_urls(pom: &str) -> PomUrls {
    parse_pom(pom).unwrap().urls
}

fn pom_properties(pom: &str) -> BTreeMap<String, String> {
    parse_pom(pom).unwrap().properties
}

fn project_properties(pom: &str) -> BTreeMap<String, String> {
    parse_pom(pom).unwrap().coordinates
}

fn parent_pom_url(pom: &str) -> Option<String> {
    match parse_pom(pom).unwrap().parent {
        PomParent::Registry(url) => Some(url),
        PomParent::None | PomParent::Unresolved => None,
    }
}

#[test]
fn pom_ignores_commented_sections_and_reads_direct_fields() {
    let pom = r#"<project xmlns="http://maven.apache.org/POM/4.0.0">
        <!-- <groupId>wrong</groupId><parent><groupId>wrong</groupId><artifactId>bad</artifactId><version>1</version></parent>
             <scm><url>https://github.com/example/old</url></scm>
             <issueManagement><url>https://github.com/example/old/issues</url></issueManagement> -->
        <groupId>example</groupId><artifactId>app</artifactId><version>1.0.0</version>
        <properties><!-- <repo>wrong</repo> --><repo>current</repo></properties>
        <scm><url>https://github.com/example/${repo}</url></scm>
        <issueManagement><url>https://github.com/example/current/issues</url></issueManagement>
    </project>"#;
    let fields = declared("maven", pom.as_bytes()).unwrap();
    assert_eq!(
        fields.repository.as_deref(),
        Some("https://github.com/example/current")
    );
    assert_eq!(
        fields.issues.as_deref(),
        Some("https://github.com/example/current/issues")
    );
    assert_eq!(
        maven_reference(pom).as_deref(),
        Some("pkg:maven/example/app")
    );
    assert!(matches!(parse_pom(pom).unwrap().parent, PomParent::None));
}

#[test]
fn malformed_or_unsafe_poms_are_rejected() {
    for pom in [
        "<project><scm><url>https://github.com/example/app</scm></project>",
        "<!DOCTYPE project [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><project>&x;</project>",
        "<!DOCTYPE project><project/>",
        "<project><groupId>a</groupId><groupId>b</groupId></project>",
        "<project><scm><url>https://github.com/example/<part>wrong</part></url></scm></project>",
    ] {
        assert!(declared("maven", pom.as_bytes()).is_err(), "{pom}");
        assert!(maven_reference(pom).is_none());
    }
}

#[test]
fn malformed_parent_pom_leaves_the_source_unmapped() {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let profile_path = directory.path().join("vulnbell.yaml");
    std::fs::write(&profile_path, format!("schema: 1\nproject_id: {project}\nname: fixture\ncomponents:\n  - ref: pkg:maven/example/app\n    version: '1.0.0'\n")).unwrap();
    let profile = crate::profile::load(&profile_path).unwrap();
    crate::engine::scan(&profile, &profile_path, true).unwrap();
    let store = Store::open(&project).unwrap();
    let child_url = registry_url("pkg:maven/example/app", Some("1.0.0")).unwrap();
    let parent_url = registry_url("pkg:maven/example/parent", Some("1.0.0")).unwrap();
    let responses = [
        (
            child_url,
            "<project><parent><groupId>example</groupId><artifactId>parent</artifactId><version>1.0.0</version></parent><artifactId>app</artifactId></project>",
        ),
        (
            parent_url,
            "<project><scm><url>https://github.com/example/wrong</scm></project>",
        ),
    ];
    let fetched_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for (url, response) in responses {
        let key = crate::digest(format!("GET:{url}:").as_bytes());
        store
            .connection
            .execute(
                "INSERT OR REPLACE INTO cache VALUES (?1,?2,NULL,?3)",
                params![key, response.as_bytes(), fetched_at],
            )
            .unwrap();
    }
    let mut http = Http::new(&store, true);
    let run = map(
        &store,
        "fixture",
        &BTreeSet::new(),
        &profile.research,
        &mut http,
        10,
    )
    .unwrap();
    assert_eq!(run.mapped_components, 0);
    assert_eq!(run.failed.len(), 1);
    let count: usize = store
        .connection
        .query_row(
            "SELECT COUNT(*) FROM discovery_sources WHERE scope='fixture'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    drop(store);
    std::fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
}

fn map_maven_fixture(child: &str, parents: &[(&str, &str)]) -> RegistryRun {
    let directory = tempfile::tempdir().unwrap();
    let project = uuid::Uuid::new_v4().to_string();
    let path = directory.path().join("vulnbell.yaml");
    std::fs::write(&path, format!("schema: 1\nproject_id: {project}\nname: fixture\ncomponents:\n  - ref: pkg:maven/example/app\n    version: '1.0.0'\n")).unwrap();
    let profile = crate::profile::load(&path).unwrap();
    crate::engine::scan(&profile, &path, true).unwrap();
    let store = Store::open(&project).unwrap();
    let fetched_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let child_url = registry_url("pkg:maven/example/app", Some("1.0.0")).unwrap();
    let mut responses = vec![(child_url, child)];
    responses.extend(parents.iter().map(|(name, body)| {
        (
            registry_url(&format!("pkg:maven/example/{name}"), Some("1.0.0")).unwrap(),
            *body,
        )
    }));
    for (url, body) in responses {
        let key = crate::digest(format!("GET:{url}:").as_bytes());
        store
            .connection
            .execute(
                "INSERT OR REPLACE INTO cache VALUES (?1,?2,NULL,?3)",
                params![key, body.as_bytes(), fetched_at],
            )
            .unwrap();
    }
    let mut http = Http::new(&store, true);
    let run = map(
        &store,
        "fixture",
        &BTreeSet::new(),
        &profile.research,
        &mut http,
        10,
    )
    .unwrap();
    let count: usize = store
        .connection
        .query_row(
            "SELECT COUNT(*) FROM discovery_sources WHERE scope='fixture'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, run.mapped_components);
    drop(store);
    std::fs::remove_dir_all(crate::store::data_root().join(project)).unwrap();
    run
}

#[test]
fn missing_parent_and_unresolved_coordinates_leave_discovery_open() {
    let missing = "<project><parent><groupId>example</groupId><artifactId>parent</artifactId><version>1.0.0</version></parent><artifactId>app</artifactId></project>";
    let run = map_maven_fixture(missing, &[]);
    assert_eq!(run.mapped_components, 0);
    assert_eq!(run.failed.len(), 1);
    assert!(run.failed[0].error.contains("parent POM unavailable"));

    for version in ["${revision}", ""] {
        let unresolved = format!(
            "<project><parent><groupId>example</groupId><artifactId>parent</artifactId><version>{version}</version></parent><artifactId>app</artifactId></project>"
        );
        let run = map_maven_fixture(&unresolved, &[]);
        assert_eq!(run.mapped_components, 0);
        assert!(
            run.failed[0]
                .error
                .contains("coordinates cannot be resolved")
        );
    }
}

#[test]
fn parent_depth_limit_does_not_assert_missing_sources() {
    let child = "<project><parent><groupId>example</groupId><artifactId>p1</artifactId><version>1.0.0</version></parent><artifactId>app</artifactId></project>";
    let bodies: Vec<String> = (1..=5).map(|n| format!("<project><parent><groupId>example</groupId><artifactId>p{}</artifactId><version>1.0.0</version></parent><artifactId>p{n}</artifactId></project>", n + 1)).collect();
    let names = ["p1", "p2", "p3", "p4", "p5"];
    let parents: Vec<_> = names
        .iter()
        .zip(&bodies)
        .map(|(name, body)| (*name, body.as_str()))
        .collect();
    let run = map_maven_fixture(child, &parents);
    assert_eq!(run.mapped_components, 0);
    assert_eq!(run.failed.len(), 1);
    assert!(run.failed[0].error.contains("traversal limit"));
}

#[test]
fn complete_child_sources_do_not_require_parent() {
    let child = "<project><parent><groupId>example</groupId><artifactId>parent</artifactId><version>${revision}</version></parent><artifactId>app</artifactId><scm><url>https://github.com/example/app</url></scm><issueManagement><url>https://github.com/example/app/issues</url></issueManagement></project>";
    let run = map_maven_fixture(child, &[]);
    assert_eq!(run.mapped_components, 1);
    assert!(run.failed.is_empty());
}

#[test]
fn pom_project_url_ignores_nested_sections_and_scm_maps_the_repository() {
    let pom = br#"<project><parent><url>https://parent.example/</url></parent>
<url>https://www.keycloak.org</url><licenses><license><url>https://license.example/</url></license></licenses>
<scm><url>https://github.com/keycloak/keycloak</url></scm>
<issueManagement><url>https://github.com/keycloak/keycloak/issues</url></issueManagement></project>"#;
    let fields = declared("maven", pom).unwrap();
    assert_eq!(fields.website.as_deref(), Some("https://www.keycloak.org"));
    assert_eq!(
        fields.repository.as_deref(),
        Some("https://github.com/keycloak/keycloak")
    );
    assert_eq!(
        fields.issues.as_deref(),
        Some("https://github.com/keycloak/keycloak/issues")
    );
}

#[test]
fn forge_links_collapse_to_one_repository_and_placeholders_are_rejected() {
    let canonical = crate::identity::canonical_repository;
    for link in [
        "https://github.com/apache/maven-compiler-plugin/issues",
        "git+https://github.com/apache/maven-compiler-plugin.git",
        "https://github.com/apache/maven-compiler-plugin/tree/main",
    ] {
        assert_eq!(
            canonical(link).as_deref(),
            Some("https://github.com/apache/maven-compiler-plugin")
        );
    }
    assert_eq!(
        canonical("https://gitlab.com/group/sub/project/-/issues").as_deref(),
        Some("https://gitlab.com/group/sub/project")
    );
    assert!(
        canonical("https://github.com/apache/maven-jar-plugin/tree/${project.scm.tag}").is_none()
    );
    for link in [
        "https://gitlab.ow2.org/asm/asm/issues",
        "https://gitlab.ow2.org/asm/asm/-/merge_requests",
    ] {
        assert_eq!(
            canonical(link).as_deref(),
            Some("https://gitlab.ow2.org/asm/asm")
        );
    }
    assert!(canonical("https://github.com/apache").is_none());
    assert_eq!(
        canonical("https://issues.apache.org/jira/browse/FREEMARKER").as_deref(),
        Some("https://issues.apache.org/jira/browse/FREEMARKER")
    );
}

#[test]
fn maven_parent_poms_supply_undeclared_scm_and_placeholders_stop_the_chain() {
    let child = "<project><parent><groupId>io.quarkus</groupId><artifactId>quarkus-extensions-parent</artifactId><version>3.40.1</version></parent><artifactId>quarkus-agroal</artifactId></project>";
    assert_eq!(
        parent_pom_url(child).as_deref(),
        Some(
            "https://repo1.maven.org/maven2/io/quarkus/quarkus-extensions-parent/3.40.1/quarkus-extensions-parent-3.40.1.pom"
        )
    );
    assert!(
        parent_pom_url("<project><parent><groupId>a</groupId><artifactId>b</artifactId><version>${revision}</version></parent></project>")
            .is_none()
    );
    let none = BTreeMap::new();
    let mut urls = pom_urls(child);
    inherit(
        &mut urls,
        pom_urls(
            "<project><url>https://quarkus.io</url><scm><url>https://github.com/quarkusio/quarkus</url></scm></project>",
        ),
        true,
    );
    let fields = resolve_pom(urls, &none);
    assert_eq!(
        fields.repository.as_deref(),
        Some("https://github.com/quarkusio/quarkus")
    );
    assert_eq!(fields.website.as_deref(), Some("https://quarkus.io"));
    let mut own = pom_urls("<project><scm><url>https://github.com/own/repo</url></scm></project>");
    inherit(
        &mut own,
        pom_urls("<project><scm><url>https://github.com/parent/repo</url></scm></project>"),
        true,
    );
    assert_eq!(
        resolve_pom(own, &none).repository.as_deref(),
        Some("https://github.com/own/repo")
    );
}

#[test]
fn scm_coordinates_map_to_https_only_where_the_forge_serves_the_same_path() {
    assert_eq!(
        scm_https("git@github.com:open-telemetry/opentelemetry-java.git").as_deref(),
        Some("https://github.com/open-telemetry/opentelemetry-java.git")
    );
    assert_eq!(
        scm_https("scm:git:git://github.com/HdrHistogram/HdrHistogram.git").as_deref(),
        Some("https://github.com/HdrHistogram/HdrHistogram.git")
    );
    assert_eq!(
        scm_https("scm:git:ssh://git@gitlab.com/group/project.git").as_deref(),
        Some("https://gitlab.com/group/project.git")
    );
    assert!(scm_https("git@git.example.internal:team/repo.git").is_none());
    assert!(scm_https("scm:svn:https://svn.apache.org/repos/asf/commons").is_none());
    let pom = "<project><scm><url>https://github.com/apache/httpcomponents-client/tree/${project.scm.tag}</url><connection>scm:git:https://git-wip-us.apache.org/repos/asf/httpcomponents-client.git</connection><tag>4.5.14</tag></scm></project>";
    assert_eq!(
        resolve_pom(pom_urls(pom), &BTreeMap::new())
            .repository
            .as_deref(),
        Some("https://github.com/apache/httpcomponents-client/tree/4.5.14")
    );
    let website_in_url = "<project><scm><connection>scm:git:git://github.com/aeshell/aesh.git</connection><url>https://aeshell.github.io/</url></scm></project>";
    assert_eq!(
        resolve_pom(pom_urls(website_in_url), &BTreeMap::new())
            .repository
            .as_deref(),
        Some("https://github.com/aeshell/aesh.git")
    );
    let ssh_only =
        "<project><scm><url>git@github.com:vert-x3/vertx-parent.git</url></scm></project>";
    assert_eq!(
        resolve_pom(pom_urls(ssh_only), &BTreeMap::new())
            .repository
            .as_deref(),
        Some("https://github.com/vert-x3/vertx-parent.git")
    );
}

#[test]
fn inherited_pom_urls_use_merged_properties_and_attribute_sections() {
    let child = "<project><parent><groupId>org.apache.commons</groupId><artifactId>commons-parent</artifactId><version>98</version></parent><artifactId>commons-io</artifactId><version>2.22.0</version><properties><!-- ids --><commons.componentid>io</commons.componentid><commons.jira.id>IO</commons.jira.id><empty/></properties></project>";
    let parent = "<project><properties><commons.repo.name>commons-${commons.componentid}</commons.repo.name><commons.jira.id>PARENT</commons.jira.id></properties><scm child.scm.url.inherit.append.path=\"false\"><url>https://gitbox.apache.org/repos/asf?p=${commons.repo.name}.git</url></scm><issueManagement><url>https://issues.apache.org/jira/browse/${commons.jira.id}</url></issueManagement><ciManagement><url>https://github.com/apache/${undefined.name}/actions</url></ciManagement></project>";
    let mut properties = pom_properties(child);
    properties.extend(project_properties(child));
    assert_eq!(
        properties.get("project.artifactId").map(String::as_str),
        Some("commons-io")
    );
    for (name, value) in pom_properties(parent) {
        properties.entry(name).or_insert(value);
    }
    let mut urls = pom_urls(child);
    inherit(&mut urls, pom_urls(parent), false);
    let resolved = resolve_pom(urls, &properties);
    assert_eq!(
        resolved.repository.as_deref(),
        Some("https://gitbox.apache.org/repos/asf?p=commons-io.git")
    );
    assert_eq!(
        resolved.issues.as_deref(),
        Some("https://issues.apache.org/jira/browse/IO")
    );
    assert_eq!(
        interpolate("https://github.com/apache/${undefined.name}", &properties),
        None
    );
    let recursive = BTreeMap::from([("a".to_owned(), "${a}".to_owned())]);
    assert_eq!(interpolate("${a}", &recursive), None);
}

#[test]
fn organisation_parents_do_not_lend_their_own_literal_urls() {
    let child = "<project><parent><groupId>org.jboss</groupId><artifactId>jboss-parent</artifactId><version>49</version></parent><groupId>org.wildfly.common</groupId><artifactId>wildfly-common</artifactId><version>1.5.4.Final</version></project>";
    let parent = "<project><groupId>org.jboss</groupId><artifactId>jboss-parent</artifactId><version>49</version><url>https://www.jboss.org</url><scm><url>https://github.com/jboss/jboss-parent-pom</url></scm><issueManagement><url>https://issues.redhat.com/</url></issueManagement></project>";
    let coordinates = project_properties(child);
    let reactor = reactor_parent(&coordinates, &project_properties(parent));
    assert!(!reactor);
    let mut urls = pom_urls(child);
    inherit(&mut urls, pom_urls(parent), reactor);
    let resolved = resolve_pom(urls, &coordinates);
    assert_eq!(
        (resolved.repository, resolved.website, resolved.issues),
        (None, None, None)
    );
    let module = "<project><parent><groupId>com.fasterxml.jackson.jakarta.rs</groupId><artifactId>jackson-jakarta-rs-providers</artifactId><version>2.21.7</version></parent><artifactId>jackson-jakarta-rs-base</artifactId></project>";
    let reactor_pom = "<project><groupId>com.fasterxml.jackson.jakarta.rs</groupId><artifactId>jackson-jakarta-rs-providers</artifactId><version>2.21.7</version></project>";
    assert!(reactor_parent(
        &project_properties(module),
        &project_properties(reactor_pom)
    ));
}

#[test]
fn registry_urls_are_exact_per_ecosystem() {
    assert_eq!(
        registry_url("pkg:maven/org.keycloak/keycloak-core", Some("26.8.1")).as_deref(),
        Some(
            "https://repo1.maven.org/maven2/org/keycloak/keycloak-core/26.8.1/keycloak-core-26.8.1.pom"
        )
    );
    assert_eq!(
        registry_url("pkg:pypi/requests", Some("2.31.0")).as_deref(),
        Some("https://pypi.org/pypi/requests/2.31.0/json")
    );
    assert!(registry_url("pkg:pypi/requests", None).is_none());
    assert!(registry_url("pkg:golang/example.com/x", Some("1.0.0")).is_none());
}
