/**
 * How the UI shows the badge of an organization's or sponsor's key
 * (`SupporterBranding`, set over the api by admins): its icon, the
 * size the icon is shown at, whether the icon stands alone, without
 * the name, and whether icon and name take the place of the app's
 * home button. The checks and constants here are the Rust crate's,
 * and the server checks again.
 */

import { base64Decode, base64Encode } from "./encoding.ts";
import { trimWhitespace } from "./whitespace.ts";
import type { SupporterTier } from "./payload.ts";
import type { SupporterBranding } from "./types.ts";
import type { Supporter } from "./verify.ts";

/** The longest icon url or path, in bytes. */
export const MAX_ICON_URL_LENGTH = 2048;

/** The longest link, in bytes. */
export const MAX_LINK_LENGTH = 2048;

/** The most bytes an uploaded icon may have (the image itself). */
export const MAX_ICON_BYTES = 256 * 1024;

/** The smallest width or height an icon can be given, in pixels. */
export const MIN_ICON_SIZE = 8;

/** The height an icon is shown at, in pixels, when none is set. */
export const DEFAULT_ICON_HEIGHT = 20;

/**
 * The largest width an icon can be given, in pixels, and the widest
 * it is shown without one.
 */
export const MAX_ICON_WIDTH = 240;

/**
 * The largest height an icon can be given, in pixels: what fits the
 * topbar of the Mogh apps (62 pixels), where it is shown.
 */
export const MAX_ICON_HEIGHT = 56;

/** The image types an uploaded icon can have. */
export const ICON_MEDIA_TYPES: readonly string[] = Object.freeze([
  "image/png",
  "image/jpeg",
  "image/gif",
  "image/webp",
  "image/svg+xml",
]);

/**
 * Whitespace and control characters, which an icon or a link never
 * has: Rust's `char::is_whitespace` and `char::is_control`.
 */
const WHITESPACE_OR_CONTROL = /[\p{White_Space}\p{Cc}]/u;

const ICON_FORM =
  "The icon is not an image url (https:// or http://), a path on the app (/...), or an uploaded image";

/**
 * Why `icon` is no icon, or `null` when it is one:
 * - an image url, `https://` or `http://` with a host;
 * - a path on the app, with a single leading `/`;
 * - an uploaded image, `data:<type>;base64,<image>` (`ICON_MEDIA_TYPES`,
 *   at most `MAX_ICON_BYTES`).
 *
 * Whitespace and control characters are refused everywhere. The icon
 * is only ever the `src` of an `<img>`.
 */
export function brandingIconProblem(icon: string): string | null {
  if (WHITESPACE_OR_CONTROL.test(icon)) return ICON_FORM;
  if (icon.startsWith("data:")) {
    const rest = icon.slice("data:".length);
    const at = rest.indexOf(";base64,");
    if (at < 0) return ICON_FORM;
    if (!ICON_MEDIA_TYPES.includes(rest.slice(0, at))) {
      return "The uploaded icon is not a png, jpeg, gif, webp or svg image";
    }
    const data = rest.slice(at + ";base64,".length);
    // By its length first: nothing far too large is decoded.
    if (data.length > Math.ceil(MAX_ICON_BYTES / 3) * 4) {
      return iconBytesProblem(Math.floor(data.length / 4) * 3);
    }
    let bytes: Uint8Array;
    try {
      bytes = base64Decode(data);
    } catch {
      return "The uploaded icon is not valid base64";
    }
    if (bytes.length === 0) return "The uploaded icon is empty";
    if (bytes.length > MAX_ICON_BYTES) return iconBytesProblem(bytes.length);
    return null;
  }
  const length = new TextEncoder().encode(icon).length;
  if (length > MAX_ICON_URL_LENGTH) {
    return `The icon url is ${length} bytes long, the most is ${MAX_ICON_URL_LENGTH}`;
  }
  for (const scheme of ["https://", "http://"]) {
    if (icon.startsWith(scheme)) {
      return icon.slice(scheme.length).split(/[/?#]/)[0] ? null : ICON_FORM;
    }
  }
  // `//host` and `/\host` name another origin.
  if (icon.startsWith("/") && !icon.startsWith("//") && !icon.startsWith("/\\")) {
    return null;
  }
  return ICON_FORM;
}

function iconBytesProblem(bytes: number): string {
  return `The uploaded icon is ${bytes} bytes, the most is ${MAX_ICON_BYTES}`;
}

/**
 * Why a width or height is refused, or `null`: unset is the default,
 * else whole pixels from `MIN_ICON_SIZE` to `MAX_ICON_WIDTH` /
 * `MAX_ICON_HEIGHT`.
 */
export function brandingSizeProblem(
  dimension: "width" | "height",
  size: number | null | undefined,
): string | null {
  if (size === null || size === undefined) return null;
  const max = dimension === "width" ? MAX_ICON_WIDTH : MAX_ICON_HEIGHT;
  if (!Number.isInteger(size) || size < MIN_ICON_SIZE || size > max) {
    return `The icon ${dimension} is ${size} pixels, it has to be ${MIN_ICON_SIZE} to ${max}`;
  }
  return null;
}

/**
 * Why `link` is no link, or `null` when it is one: a web address,
 * `https://` or `http://` with a host, of at most `MAX_LINK_LENGTH`
 * bytes, without whitespace or control characters. Nothing else is
 * opened by a click on the badge: no path on the app, and no other
 * scheme (`javascript:`, `data:`).
 */
export function brandingLinkProblem(link: string): string | null {
  const form = "The link is not a web address (https:// or http://)";
  if (WHITESPACE_OR_CONTROL.test(link)) return form;
  const length = new TextEncoder().encode(link).length;
  if (length > MAX_LINK_LENGTH) {
    return `The link is ${length} bytes long, the most is ${MAX_LINK_LENGTH}`;
  }
  for (const scheme of ["https://", "http://"]) {
    if (link.startsWith(scheme)) {
      return link.slice(scheme.length).split(/[/?#]/)[0] ? null : form;
    }
  }
  return form;
}

/**
 * Why the server would refuse the branding, or `null`. The icon and
 * the link are trimmed first, as the server trims them (Rust's
 * `str::trim`).
 */
export function brandingProblem(branding: SupporterBranding): string | null {
  const icon = branding.icon && trimWhitespace(branding.icon);
  const link = branding.link && trimWhitespace(branding.link);
  return (
    (icon ? brandingIconProblem(icon) : null) ??
    brandingSizeProblem("width", branding.icon_width) ??
    brandingSizeProblem("height", branding.icon_height) ??
    (link ? brandingLinkProblem(link) : null)
  );
}

/**
 * The branding as it is sent and kept: the icon and the link trimmed,
 * what is unset left out, and the name hidden only with an icon.
 */
export function normalizeBranding(
  branding: Partial<SupporterBranding> | null | undefined,
): SupporterBranding {
  const icon = branding?.icon && trimWhitespace(branding.icon);
  const normalized: SupporterBranding = {
    replace_home: !!branding?.replace_home,
    // Without an icon there is nothing to stand for the name.
    hide_name: !!icon && !!branding?.hide_name,
    uppercase_name: !!branding?.uppercase_name,
  };
  if (icon) normalized.icon = icon;
  if (typeof branding?.icon_width === "number") {
    normalized.icon_width = branding.icon_width;
  }
  if (typeof branding?.icon_height === "number") {
    normalized.icon_height = branding.icon_height;
  }
  const link = branding?.link && trimWhitespace(branding.link);
  if (link) normalized.link = link;
  return normalized;
}

/** What a verified organization's or sponsor's key shows. */
export interface SupporterBrand {
  /** The supporter's name, from the key. */
  name: string;
  tier: SupporterTier;
  /** The organization's icon, if one is set: the `src` of an `<img>`. */
  icon?: string;
  /**
   * The width to show the icon at, in pixels, if one is set. Without
   * one: as wide as the image is at the height it is shown at. Only
   * with an icon.
   */
  iconWidth?: number;
  /**
   * The height to show the icon at, in pixels, if one is set. Without
   * one: `DEFAULT_ICON_HEIGHT`. Only with an icon.
   */
  iconHeight?: number;
  /**
   * Where a click on the badge leads, in a new tab, if a link is set:
   * the `href` of an `<a>`. Without one: `SUPPORTER_URL`.
   */
  link?: string;
  /**
   * Whether icon and name take the place of the app's home button
   * (which still leads to `/`), instead of showing as a badge.
   */
  replaceHome: boolean;
  /**
   * Whether the name is left out where the brand shows, for an icon
   * which includes it. Only ever with an icon, which then stands
   * for the name: show the name again if the icon fails to load.
   */
  hideName: boolean;
  /**
   * Whether the name shows in capital letters where the brand shows
   * (a `text-transform`, the name itself stays as the key has it).
   */
  uppercaseName: boolean;
}

/**
 * The brand a verified key shows with the instance's branding. Only
 * the key of an organization or sponsor has one: `null` for an
 * individual's key, without a key (`null`), or while the key is being
 * verified (`undefined`). The branding comes from the server and is
 * checked again here: an icon or size which is not valid is dropped.
 */
export function supporterBrand(
  supporter: Supporter | null | undefined,
  branding: Partial<SupporterBranding> | null | undefined,
): SupporterBrand | null {
  if (!supporter || supporter.tier === "individual") return null;
  const brand: SupporterBrand = {
    name: supporter.name,
    tier: supporter.tier,
    replaceHome: branding?.replace_home === true,
    hideName: false,
    uppercaseName: branding?.uppercase_name === true,
  };
  const link =
    typeof branding?.link === "string" ? trimWhitespace(branding.link) : "";
  if (link && brandingLinkProblem(link) === null) brand.link = link;
  const icon =
    typeof branding?.icon === "string" ? trimWhitespace(branding.icon) : "";
  // The size is the icon's: without one there is nothing to size.
  if (!icon || brandingIconProblem(icon) !== null) return brand;
  brand.icon = icon;
  brand.hideName = branding?.hide_name === true;
  const width = branding?.icon_width;
  if (typeof width === "number" && brandingSizeProblem("width", width) === null) {
    brand.iconWidth = width;
  }
  const height = branding?.icon_height;
  if (typeof height === "number" && brandingSizeProblem("height", height) === null) {
    brand.iconHeight = height;
  }
  return brand;
}

/**
 * An uploaded image as the `data:` url an icon is kept as. Rejects
 * with the reason for another type than `ICON_MEDIA_TYPES`, an empty
 * file, or more than `MAX_ICON_BYTES`.
 */
export async function iconDataUrl(file: Blob): Promise<string> {
  if (!ICON_MEDIA_TYPES.includes(file.type)) {
    throw new Error("The image has to be a png, jpeg, gif, webp or svg");
  }
  if (file.size === 0) {
    throw new Error("The image is empty");
  }
  if (file.size > MAX_ICON_BYTES) {
    throw new Error(
      `The image is ${Math.ceil(file.size / 1024)} KB, the most is ${MAX_ICON_BYTES / 1024} KB`,
    );
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  return `data:${file.type};base64,${base64Encode(bytes)}`;
}
