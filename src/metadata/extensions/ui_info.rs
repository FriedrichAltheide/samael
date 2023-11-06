use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

use crate::metadata::LocalizedString;

const NAME: &str = "mdui:UIInfo";
const SCHEMA: (&str, &str) = ("xmlns:mdui", "urn:oasis:names:tc:SAML:metadata:ui");

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Logo {
    #[serde(alias = "@width")]
    pub width: Option<usize>,
    #[serde(alias = "@height")]
    pub height: Option<usize>,
    #[serde(rename = "$value")]
    pub logo_url: String,
}

impl Logo {
    pub fn new(logo_url: String, width: usize, height: usize) -> Self {
        Self {
            width: Some(width),
            height: Some(height),
            logo_url,
        }
    }

    pub fn to_xml(&self, element_name: &str) -> Result<Event, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(element_name);
        if let Some(x) = &self.width {
            root.push_attribute(("width", x.to_string().as_ref()));
        }
        if let Some(x) = &self.height {
            root.push_attribute(("height", x.to_string().as_ref()));
        }
        writer.write_event(Event::Start(root))?;
        writer.write_event(Event::Text(BytesText::from_escaped(&self.logo_url)))?;
        writer.write_event(Event::End(BytesEnd::new(element_name)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[derive(Clone, Debug, Deserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct UiInfo {
    #[serde(rename = "DisplayName", default)]
    pub display_name: Vec<LocalizedString>,
    #[serde(rename = "Description", default)]
    pub description: Vec<LocalizedString>,
    #[serde(rename = "Keywords", default)]
    pub keywords: Vec<LocalizedString>,
    #[serde(rename = "Logo", default)]
    pub logo: Vec<Logo>,
    #[serde(rename = "InformationURL", default)]
    pub information_url: Vec<LocalizedString>,
    #[serde(rename = "PrivacyStatementURL", default)]
    pub privacy_statement_url: Vec<LocalizedString>,
}

impl TryFrom<UiInfo> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: UiInfo) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&UiInfo> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &UiInfo) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(NAME);

        root.push_attribute(SCHEMA);

        writer.write_event(Event::Start(root))?;

        for item in &value.display_name {
            writer.write_event(item.to_xml("mdui:DisplayName")?)?;
        }
        for item in &value.description {
            writer.write_event(item.to_xml("mdui:Description")?)?;
        }
        for item in &value.keywords {
            writer.write_event(item.to_xml("mdui:Keywords")?)?;
        }
        for item in &value.logo {
            writer.write_event(item.to_xml("mdui:Logo")?)?;
        }
        for item in &value.information_url {
            writer.write_event(item.to_xml("mdui:InformationURL")?)?;
        }
        for item in &value.privacy_statement_url {
            writer.write_event(item.to_xml("mdui:PrivacyStatementURL")?)?;
        }

        writer.write_event(Event::End(BytesEnd::new(NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
