//! How the UI shows the badge of an organization's or sponsor's key
//! ([SupporterBranding]): its icon, the size the icon is shown at,
//! where a click on the badge leads, whether the icon stands alone,
//! without the name, and whether icon and name take the place of
//! the app's home button. Set by
//! admins over the api (`SetSupporterBranding`), kept
//! by the app, and read by every user's browser
//! (`GetSupporterBranding`), which applies it only for a key it
//! verified as an organization's or sponsor's.

use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use typeshare::typeshare;

/// The longest icon url or path, in bytes.
pub const MAX_ICON_URL_LENGTH: usize = 2048;

/// The longest link, in bytes.
pub const MAX_LINK_LENGTH: usize = 2048;

/// The most bytes an uploaded icon may have (the image itself, not
/// its `data:` url).
pub const MAX_ICON_BYTES: usize = 256 * 1024;

/// The smallest width or height an icon can be given, in pixels.
pub const MIN_ICON_SIZE: u32 = 8;

/// The height an icon is shown at, in pixels, when none is set.
pub const DEFAULT_ICON_HEIGHT: u32 = 20;

/// The largest width an icon can be given, in pixels, and the
/// widest it is shown without one.
pub const MAX_ICON_WIDTH: u32 = 240;

/// The largest height an icon can be given, in pixels: what fits
/// the topbar of the Mogh apps (62 pixels), where it is shown.
pub const MAX_ICON_HEIGHT: u32 = 56;

/// The image types an uploaded icon (a `data:` url) can have.
pub const ICON_MEDIA_TYPES: [&str; 5] = [
  "image/png",
  "image/jpeg",
  "image/gif",
  "image/webp",
  "image/svg+xml",
];

/// How the UI shows the badge of an organization's or sponsor's
/// key. Nothing in it is secret: every user's browser reads it.
///
/// The typescript package has the same checks (`brandingProblem`)
/// and constants.
#[typeshare]
#[derive(
  Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq,
)]
pub struct SupporterBranding {
  /// The organization's icon, shown in place of the heart: an image
  /// url (`https://` or `http://`), a path on the app (`/...`), or
  /// an uploaded image as a `data:image/...;base64,` url
  /// ([ICON_MEDIA_TYPES], at most [MAX_ICON_BYTES]). `None`: the
  /// heart.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub icon: Option<String>,
  /// The width the icon is shown at, in pixels ([MIN_ICON_SIZE] to
  /// [MAX_ICON_WIDTH]). `None`: as wide as the image is at the
  /// height it is shown at (its proportions are kept either way).
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub icon_width: Option<u32>,
  /// The height the icon is shown at, in pixels ([MIN_ICON_SIZE] to
  /// [MAX_ICON_HEIGHT]). `None`: [DEFAULT_ICON_HEIGHT].
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub icon_height: Option<u32>,
  /// Where a click on the badge leads, opened in a new tab: a web
  /// address (`https://` or `http://`), eg. the organization's own
  /// site. `None`: the supporter page of mogh.tech. Not used while
  /// the brand is the home button, which leads home.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub link: Option<String>,
  /// Show the icon and the supporter's name in place of the app's
  /// home button (which still leads to `/`), instead of as a badge.
  #[serde(default)]
  pub replace_home: bool,
  /// Leave the supporter's name out where the brand shows (the
  /// badge, the home button): for an icon which includes the name.
  /// Only with an icon, which then stands for the name: without one
  /// the name always shows.
  #[serde(default)]
  pub hide_name: bool,
  /// Show the supporter's name in capital letters where the brand
  /// shows (the badge, the home button), like the apps write their
  /// own names. The name itself stays as the key has it.
  #[serde(default)]
  pub uppercase_name: bool,
}

/// Why a [SupporterBranding] is refused. Never echoes the icon.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BrandingError {
  #[error(
    "The icon is not an image url (https:// or http://), a path on the app (/...), or an uploaded image"
  )]
  IconForm,
  #[error(
    "The icon url is {0} bytes long, the most is {MAX_ICON_URL_LENGTH}"
  )]
  IconUrlLength(usize),
  #[error(
    "The uploaded icon is not a png, jpeg, gif, webp or svg image"
  )]
  IconMediaType,
  #[error("The uploaded icon is not valid base64")]
  IconEncoding,
  #[error("The uploaded icon is empty")]
  IconEmpty,
  #[error(
    "The uploaded icon is {0} bytes, the most is {MAX_ICON_BYTES}"
  )]
  IconBytes(usize),
  #[error(
    "The icon {dimension} is {got} pixels, it has to be {MIN_ICON_SIZE} to {max}"
  )]
  IconSize {
    dimension: &'static str,
    got: u32,
    max: u32,
  },
  #[error("The link is not a web address (https:// or http://)")]
  LinkForm,
  #[error(
    "The link is {0} bytes long, the most is {MAX_LINK_LENGTH}"
  )]
  LinkLength(usize),
}

impl SupporterBranding {
  /// Whether nothing is set: the heart, as a badge.
  pub fn is_default(&self) -> bool {
    *self == SupporterBranding::default()
  }

  /// Checks the branding, and returns it as it is kept: the icon
  /// and the link trimmed, an empty one as none, and the name hidden
  /// only with an icon. See [check_icon] for the icon,
  /// [MIN_ICON_SIZE], [MAX_ICON_WIDTH] and [MAX_ICON_HEIGHT] for
  /// its size, and [check_link] for the link.
  pub fn validated(self) -> Result<SupporterBranding, BrandingError> {
    let icon = match self.icon.as_deref().map(str::trim) {
      None | Some("") => None,
      Some(icon) => {
        check_icon(icon)?;
        Some(icon.to_string())
      }
    };
    check_size("width", self.icon_width, MAX_ICON_WIDTH)?;
    check_size("height", self.icon_height, MAX_ICON_HEIGHT)?;
    let link = match self.link.as_deref().map(str::trim) {
      None | Some("") => None,
      Some(link) => {
        check_link(link)?;
        Some(link.to_string())
      }
    };
    Ok(SupporterBranding {
      link,
      // Without an icon there is nothing to stand for the name.
      hide_name: self.hide_name && icon.is_some(),
      icon,
      icon_width: self.icon_width,
      icon_height: self.icon_height,
      replace_home: self.replace_home,
      uppercase_name: self.uppercase_name,
    })
  }

  /// How the icon is given, for logs: `none`, `url` or `uploaded`.
  /// Never the icon itself, an uploaded one is the whole image.
  pub fn icon_kind(&self) -> &'static str {
    match &self.icon {
      None => "none",
      Some(icon) if icon.starts_with("data:") => "uploaded",
      Some(_) => "url",
    }
  }
}

fn check_size(
  dimension: &'static str,
  size: Option<u32>,
  max: u32,
) -> Result<(), BrandingError> {
  match size {
    Some(got) if !(MIN_ICON_SIZE..=max).contains(&got) => {
      Err(BrandingError::IconSize {
        dimension,
        got,
        max,
      })
    }
    _ => Ok(()),
  }
}

/// Checks an icon. It is one of:
/// - an image url: `https://` or `http://` (lowercase) and a host,
///   at most [MAX_ICON_URL_LENGTH] bytes;
/// - a path on the app: a single leading `/` (`//host` and `/\host`
///   name another origin), at most [MAX_ICON_URL_LENGTH] bytes;
/// - an uploaded image: `data:<type>;base64,<image>`, with a type
///   of [ICON_MEDIA_TYPES] and 1 to [MAX_ICON_BYTES] bytes of image
///   in padded base64.
///
/// Whitespace and control characters are refused everywhere. The
/// icon is only ever the `src` of an `<img>`, where neither a url
/// nor an svg can run a script.
pub fn check_icon(icon: &str) -> Result<(), BrandingError> {
  if icon.chars().any(|c| c.is_whitespace() || c.is_control()) {
    return Err(BrandingError::IconForm);
  }
  if let Some(rest) = icon.strip_prefix("data:") {
    let (media_type, data) =
      rest.split_once(";base64,").ok_or(BrandingError::IconForm)?;
    if !ICON_MEDIA_TYPES.contains(&media_type) {
      return Err(BrandingError::IconMediaType);
    }
    // By its length first: nothing far too large is decoded.
    let most = MAX_ICON_BYTES.div_ceil(3) * 4;
    if data.len() > most {
      return Err(BrandingError::IconBytes(data.len() / 4 * 3));
    }
    let bytes = BASE64
      .decode(data.as_bytes())
      .map_err(|_| BrandingError::IconEncoding)?;
    if bytes.is_empty() {
      return Err(BrandingError::IconEmpty);
    }
    if bytes.len() > MAX_ICON_BYTES {
      return Err(BrandingError::IconBytes(bytes.len()));
    }
    return Ok(());
  }
  if icon.len() > MAX_ICON_URL_LENGTH {
    return Err(BrandingError::IconUrlLength(icon.len()));
  }
  if let Some(has_host) = web_address_has_host(icon) {
    return if has_host {
      Ok(())
    } else {
      Err(BrandingError::IconForm)
    };
  }
  if icon.starts_with('/')
    && !icon.starts_with("//")
    && !icon.starts_with("/\\")
  {
    return Ok(());
  }
  Err(BrandingError::IconForm)
}

/// For a web address, `https://` or `http://` (lowercase), whether
/// it names a host. `None`: it is no web address.
fn web_address_has_host(url: &str) -> Option<bool> {
  ["https://", "http://"].iter().find_map(|scheme| {
    let rest = url.strip_prefix(scheme)?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    Some(!host.is_empty())
  })
}

/// Checks a link: a web address, `https://` or `http://` (lowercase)
/// and a host, of at most [MAX_LINK_LENGTH] bytes, without
/// whitespace or control characters. Nothing else can be opened by a
/// click on the badge: no path on the app, and no other scheme
/// (`javascript:`, `data:`).
pub fn check_link(link: &str) -> Result<(), BrandingError> {
  if link.chars().any(|c| c.is_whitespace() || c.is_control()) {
    return Err(BrandingError::LinkForm);
  }
  if link.len() > MAX_LINK_LENGTH {
    return Err(BrandingError::LinkLength(link.len()));
  }
  match web_address_has_host(link) {
    Some(true) => Ok(()),
    _ => Err(BrandingError::LinkForm),
  }
}
