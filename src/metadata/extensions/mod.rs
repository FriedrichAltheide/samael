use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

mod ui_info;
pub use self::ui_info::*;

const NAME: &str = "md:Extensions";

#[derive(Clone, Debug, Deserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Extensions {
    #[serde(rename = "UIInfo")]
    pub ui_info: Option<UiInfo>,
}

impl TryFrom<Extensions> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: Extensions) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Extensions> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &Extensions) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(NAME);

        writer.write_event(Event::Start(root))?;

        if let Some(ui_info) = &value.ui_info {
            let event: Event<'_> = ui_info.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
