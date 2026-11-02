use pulldown_cmark::{Event, HeadingLevel, Options, Parser, Tag, TagEnd};
use std::collections::HashSet;

// Approximate the A4 layout in thousandths of an em; fonts can render differently.
const ESTIMATED_LINE_WIDTH: usize = 48_000;
const PAGE_LINES: usize = 38;

struct List {
    index: usize,
    after_heading: bool,
    lines: usize,
    item_width: Option<usize>,
    item_breaks: usize,
    item_paragraphs: usize,
}

fn finish_segment(list: &mut List, force_line: bool) {
    let Some(width) = list.item_width else {
        return;
    };
    if width > 0 || list.item_breaks > 0 || force_line {
        let lines = width.saturating_add(ESTIMATED_LINE_WIDTH - 1) / ESTIMATED_LINE_WIDTH;
        list.lines = list.lines.saturating_add(lines.max(1) + list.item_breaks);
    }
    list.item_width = Some(0);
    list.item_breaks = 0;
}

fn estimated_width(text: &str, monospace: bool) -> usize {
    text.chars().fold(0_usize, |width, character| {
        let advance = if monospace {
            650
        } else {
            match character {
                'i' | 'l' | 'I' | '!' | '.' | ',' | ':' | ';' | '\'' | '|' | '`' | ' ' => 300,
                'f' | 'r' | 't' | '(' | ')' | '[' | ']' => 450,
                'm' | 'w' | 'M' | 'W' | '@' | '%' | '&' => 1000,
                'A'..='Z' => 750,
                '0'..='9' => 620,
                character if character.is_ascii() => 600,
                _ => 1050,
            }
        };
        width.saturating_add(advance)
    })
}

/// Estimate only lists that follow headings; this leaves ordinary Markdown unchanged.
pub(super) fn oversized_lists(markdown: &str, options: Options) -> HashSet<usize> {
    let mut lists = Vec::<List>::new();
    let mut oversized = HashSet::new();
    let mut next_index = 0;
    let mut after_heading = false;
    let mut in_code_block = false;
    for event in Parser::new_ext(markdown, options) {
        match event {
            Event::End(TagEnd::Heading(HeadingLevel::H2 | HeadingLevel::H3)) => {
                after_heading = true;
            }
            Event::Start(Tag::List(_)) => {
                lists.push(List {
                    index: next_index,
                    after_heading,
                    lines: 0,
                    item_width: None,
                    item_breaks: 0,
                    item_paragraphs: 0,
                });
                next_index += 1;
                after_heading = false;
            }
            Event::End(TagEnd::List(_)) => {
                if let Some(list) = lists.pop() {
                    if list.after_heading && list.lines >= PAGE_LINES {
                        oversized.insert(list.index);
                    }
                    if let Some(parent) = lists.last_mut() {
                        parent.lines = parent.lines.saturating_add(list.lines);
                    }
                }
                after_heading = false;
            }
            Event::Start(Tag::Item) => {
                if let Some(list) = lists.last_mut() {
                    list.item_width = Some(0);
                    list.item_breaks = 0;
                    list.item_paragraphs = 0;
                }
                after_heading = false;
            }
            Event::End(TagEnd::Paragraph) => {
                if let Some(list) = lists.last_mut()
                    && list.item_width.is_some()
                {
                    finish_segment(list, true);
                    list.item_paragraphs += 1;
                }
                after_heading = false;
            }
            Event::End(TagEnd::Item) => {
                if let Some(list) = lists.last_mut()
                    && list.item_width.is_some()
                {
                    finish_segment(list, list.item_paragraphs == 0);
                    let extra_paragraphs = list.item_paragraphs.saturating_sub(1);
                    list.lines = list
                        .lines
                        .saturating_add(extra_paragraphs.saturating_add(2) / 3);
                    list.item_width = None;
                }
                after_heading = false;
            }
            Event::Text(value) | Event::Html(value) | Event::InlineHtml(value) => {
                if let Some(list) = lists.last_mut()
                    && let Some(width) = list.item_width.as_mut()
                {
                    *width = width.saturating_add(estimated_width(&value, in_code_block));
                    if in_code_block {
                        list.item_breaks =
                            list.item_breaks.saturating_add(value.matches('\n').count());
                    }
                }
                after_heading = false;
            }
            Event::Code(value) => {
                if let Some(list) = lists.last_mut()
                    && let Some(width) = list.item_width.as_mut()
                {
                    *width = width.saturating_add(estimated_width(&value, true));
                }
                after_heading = false;
            }
            Event::SoftBreak => {
                if let Some(list) = lists.last_mut()
                    && let Some(width) = list.item_width.as_mut()
                {
                    *width = width.saturating_add(300);
                }
                after_heading = false;
            }
            Event::HardBreak => {
                if let Some(list) = lists.last_mut() {
                    list.item_breaks = list.item_breaks.saturating_add(1);
                }
                after_heading = false;
            }
            Event::Start(Tag::CodeBlock(_)) => {
                in_code_block = true;
                after_heading = false;
            }
            Event::End(TagEnd::CodeBlock) => {
                in_code_block = false;
                after_heading = false;
            }
            _ => after_heading = false,
        }
    }
    oversized
}

pub(super) fn wrap_oversized<'a>(
    events: impl Iterator<Item = Event<'a>>,
    oversized: HashSet<usize>,
) -> impl Iterator<Item = Event<'a>> {
    let mut next_index = 0;
    let mut lists = Vec::new();
    events.flat_map(move |event| {
        let mut before = None;
        let mut after = None;
        match &event {
            Event::Start(Tag::List(_)) => {
                let wrap = oversized.contains(&next_index);
                next_index += 1;
                lists.push(wrap);
                if wrap {
                    before = Some(Event::Html("<div class=\"oversized-list\">".into()));
                }
            }
            Event::End(TagEnd::List(_)) if lists.pop().unwrap_or(false) => {
                after = Some(Event::Html("</div>".into()));
            }
            _ => {}
        }
        before
            .into_iter()
            .chain(std::iter::once(event))
            .chain(after)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimates_visible_nested_and_multiline_items() {
        let mut markdown = String::from("## Short\n\n- [Reference](https://example.org/");
        markdown.push_str(&"url".repeat(200));
        markdown.push_str(")\n\n## Long\n\n");
        for _ in 0..20 {
            markdown.push_str(&format!("- {}\n", "evidence ".repeat(28)));
        }
        markdown.push_str("\n### Nested\n\n- Parent\n");
        for _ in 0..40 {
            markdown.push_str("  - Nested evidence\n");
        }
        let oversized = oversized_lists(&markdown, Options::empty());
        assert!(
            !oversized.contains(&0),
            "link destinations do not affect layout"
        );
        assert!(
            oversized.contains(&1),
            "multiline list should be splittable"
        );
        assert!(
            oversized.contains(&2),
            "nested list contributes to its parent"
        );
    }

    #[test]
    fn counts_separate_paragraphs_within_list_items() {
        let mut markdown = String::from("### Finding\n\n");
        for _ in 0..10 {
            markdown.push_str("- First paragraph.\n");
            for _ in 0..5 {
                markdown.push_str("\n  Another paragraph.\n");
            }
            markdown.push('\n');
        }
        assert!(oversized_lists(&markdown, Options::empty()).contains(&0));
    }

    #[test]
    fn estimates_narrow_and_wide_text_without_counting_link_urls() {
        let mut narrow = String::from("## Narrow\n\n");
        for _ in 0..20 {
            narrow.push_str(&format!("- {}\n", "i".repeat(100)));
        }
        assert!(oversized_lists(&narrow, Options::empty()).is_empty());
        let mut wide = String::from("## Wide\n\n");
        for _ in 0..30 {
            wide.push_str(&format!("- `{}`\n", "0123456789abcdef".repeat(9)));
        }
        assert!(oversized_lists(&wide, Options::empty()).contains(&0));
    }

    #[test]
    fn estimates_unicode_and_hard_breaks() {
        let mut markdown = String::from("### Unicode\n\n");
        for _ in 0..20 {
            markdown.push_str(&format!("- {}\n", "字".repeat(100)));
        }
        assert!(oversized_lists(&markdown, Options::empty()).contains(&0));
        let mut markdown = String::from("## Breaks\n\n- First");
        for _ in 0..40 {
            markdown.push_str("  \n  Next");
        }
        assert!(oversized_lists(&markdown, Options::empty()).contains(&0));
    }
}
