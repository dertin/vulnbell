use crate::profile::Language;
use anyhow::{Result, bail};

pub(super) const LINK: &str = "[VulnBell](https://github.com/dertin/vulnbell)";
const URL: &str = "https://github.com/dertin/vulnbell";

fn footer(language: Language) -> &'static str {
    match language {
        Language::Es => {
            "\n\n---\n\n*Generado con [VulnBell](https://github.com/dertin/vulnbell).*\n"
        }
        Language::En => {
            "\n\n---\n\n*Generated with [VulnBell](https://github.com/dertin/vulnbell).*\n"
        }
    }
}

pub(crate) fn without_footer(markdown: &str) -> &str {
    let Some(body) = [footer(Language::Es), footer(Language::En)]
        .into_iter()
        .find_map(|footer| markdown.strip_suffix(footer))
    else {
        return markdown;
    };
    let footer_start = body.len();
    let inside_code = pulldown_cmark::Parser::new(markdown)
        .into_offset_iter()
        .any(|(event, range)| {
            matches!(
                event,
                pulldown_cmark::Event::Start(pulldown_cmark::Tag::CodeBlock(_))
            ) && range.start <= footer_start
                && footer_start < range.end
        });
    if inside_code { markdown } else { body }
}

pub(crate) fn finish(markdown: &str, language: Language) -> String {
    format!(
        "{}{}",
        without_footer(markdown).trim_end_matches('\n'),
        footer(language)
    )
}

pub(super) fn custom(markdown: &str, language: Language) -> Result<String> {
    let markdown = without_footer(markdown);
    let heading = format!("# {LINK}");
    let mut result = String::new();
    let first_content = markdown
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('>'));
    let branded = first_content.is_some_and(|line| {
        line.starts_with(&heading)
            || line == format!("*Generado con {LINK}.*")
            || line == format!("*Generated with {LINK}.*")
    });
    if !branded {
        let attribution = match language {
            Language::Es => "Generado con",
            Language::En => "Generated with",
        };
        result.push_str(&format!("*{attribution} {LINK}.*\n\n"));
    }
    result.push_str(markdown);
    let result = finish(&result, language);
    let footer_start = result.len() - footer(language).len();
    let visible_link = pulldown_cmark::Parser::new(&result)
        .into_offset_iter()
        .any(|(event, range)| {
            range.start >= footer_start
                && matches!(event, pulldown_cmark::Event::Start(pulldown_cmark::Tag::Link { dest_url, .. }) if dest_url.as_ref() == URL)
        });
    if !visible_link {
        bail!("report footer could not be rendered; close any unfinished Markdown code fence");
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{LINK, custom, finish, footer, without_footer};
    use crate::profile::Language;

    #[test]
    fn custom_reports_have_one_attribution_and_one_closing() {
        let original = "# Custom report\n\nEvidence.\n";
        let report = custom(original, Language::Es).unwrap();
        assert!(report.starts_with(&format!("*Generado con {LINK}.*\n\n")));
        assert!(report.ends_with(&format!("*Generado con {LINK}.*\n")));
        assert_eq!(custom(&report, Language::Es).unwrap(), report);
        let edited = format!("{}\nAdditional findings.\n", finish(original, Language::Es));
        let report = custom(&edited, Language::Es).unwrap();
        assert_eq!(report.matches("*Generado con [VulnBell]").count(), 3);
        assert!(report.find("Additional findings.").unwrap() < report.rfind("---").unwrap());
        assert_eq!(
            without_footer(&finish(original, Language::En)),
            original.trim_end_matches('\n')
        );
    }

    #[test]
    fn custom_content_and_later_headings_are_not_treated_as_branding() {
        let quoted = format!("```markdown\n{}\n```", finish("Evidence", Language::En));
        let input = format!("# Other report\n\n{quoted}\n\n# {LINK}\n");
        let output = custom(&input, Language::En).unwrap();
        assert!(output.starts_with(&format!("*Generated with {LINK}.*\n\n")));
        assert!(output.contains(&quoted));
        assert!(output.ends_with(&format!("*Generated with {LINK}.*\n")));
        let unclosed = format!("```markdown\n{}", footer(Language::En));
        assert_eq!(without_footer(&unclosed), unclosed);
        assert!(custom(&unclosed, Language::En).is_err());
    }
}
