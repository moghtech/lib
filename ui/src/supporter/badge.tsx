import { ReactElement, ReactNode, useSyncExternalStore } from "react";
import { Button, ButtonProps, Group, HoverCard, Text } from "@mantine/core";
import { Heart } from "lucide-react";
import {
  DEFAULT_ICON_HEIGHT,
  MAX_ICON_WIDTH,
  SUPPORTER_URL,
  supporterBrand,
} from "mogh_supporter";
import type { Supporter, SupporterBrand, Types } from "mogh_supporter";

export interface SupporterBrandIconProps {
  /** From `supporterBrand` / `useSupporterBrand`. */
  brand: SupporterBrand;
  /**
   * The widest the icon is shown here, whatever the branding sets:
   * for a narrow place, eg. the topbar of a small screen. In pixels,
   * or a css length (eg. `clamp(32px, 20vw, 110px)`). Default
   * `MAX_ICON_WIDTH`.
   */
  maxWidth?: number | string;
  /** Shown when the brand has no icon, or it fails to load. */
  fallback?: ReactNode;
}

/**
 * The height `SupporterBrandIcon` shows a brand's icon at, in pixels,
 * for the place to make room: what the branding sets, else
 * `DEFAULT_ICON_HEIGHT` (20).
 */
export function supporterIconHeight(brand: SupporterBrand): number {
  return brand.iconHeight ?? DEFAULT_ICON_HEIGHT;
}

/**
 * The icons which failed to load on this page. A brand whose icon
 * failed shows without it, everywhere it shows, and with its name
 * (`useShownSupporterBrand`).
 */
const failedIcons = new Set<string>();
const failedListeners = new Set<() => void>();

function iconFailed(icon: string) {
  if (failedIcons.has(icon)) return;
  failedIcons.add(icon);
  failedListeners.forEach((listener) => listener());
}

function subscribeFailed(listener: () => void) {
  failedListeners.add(listener);
  return () => {
    failedListeners.delete(listener);
  };
}

/** Whether `icon` failed to load on this page. */
function useIconFailed(icon: string | undefined): boolean {
  return useSyncExternalStore(
    subscribeFailed,
    () => icon !== undefined && failedIcons.has(icon),
    () => false,
  );
}

/**
 * The brand of a verified key with the instance's branding
 * (`supporterBrand`), as it shows on this page: a name which the
 * branding hides is shown again when the icon standing for it failed
 * to load. `null` without an organization's or sponsor's key.
 */
export function useShownSupporterBrand(
  supporter: Supporter | null | undefined,
  branding: Partial<Types.SupporterBranding> | null | undefined,
): SupporterBrand | null {
  const brand = supporterBrand(supporter, branding);
  const failed = useIconFailed(brand?.icon);
  return brand?.hideName && failed ? { ...brand, hideName: false } : brand;
}

/**
 * The icon of an organization's brand, keeping the image's
 * proportions: as high as its branding sets (else 20 pixels,
 * `DEFAULT_ICON_HEIGHT`), and as wide as its branding sets (else as
 * the image is at that height, up to `maxWidth`).
 */
export function SupporterBrandIcon({
  brand,
  maxWidth = MAX_ICON_WIDTH,
  fallback = null,
}: SupporterBrandIconProps) {
  const icon = brand.icon;
  const failed = useIconFailed(icon);
  if (!icon || failed) {
    return <>{fallback}</>;
  }
  return (
    <img
      src={icon}
      alt={brand.name}
      onError={() => iconFailed(icon)}
      style={{
        height: supporterIconHeight(brand),
        width: brand.iconWidth ?? "auto",
        maxWidth,
        objectFit: "contain",
        display: "block",
        flexShrink: 0,
      }}
      data-testid="supporter-icon"
    />
  );
}

/** The height of the badge, a button, in pixels. */
const BADGE_HEIGHT = 36;

/**
 * Besides its own, the props of the button the badge is (eg.
 * `visibleFrom`, to leave it out on a small screen).
 */
export interface SupporterBadgeProps extends Omit<
  ButtonProps,
  "children" | "leftSection" | "rightSection"
> {
  /** From `useSupporter`. Nothing is rendered while `undefined`. */
  supporter: Supporter | null | undefined;
  /**
   * From `useSupporterBranding`: how the badge of an organization or
   * sponsor is shown (its icon and size, whether the icon stands
   * alone, without the name, and where a click on it leads). The
   * heart without it, and always for an individual.
   */
  branding?: Types.SupporterBranding | null;
  /**
   * Where the offer leads, and a badge whose branding sets no link of
   * its own. Default `SUPPORTER_URL`.
   */
  href?: string;
  /**
   * The app's words for a supporter's badge, shown in its hover card
   * under the thanks: eg. what the support does for the app. Can be
   * made from the supporter. Without it the card is the thanks alone.
   */
  supportedText?: ReactNode | ((supporter: Supporter) => ReactNode);
  /**
   * The app's words for "Become a supporter", shown in its hover
   * card: eg. what supporting the app means. No card without it.
   * A key unlocks nothing and does not expire: don't say it does.
   */
  unsupportedText?: ReactNode;
}

/** A hover card under the supporter button, in the topbar's way. */
function SupporterHoverCard({
  title,
  text,
  children,
}: {
  title?: ReactNode;
  text?: ReactNode;
  /** The button. */
  children: ReactElement;
}) {
  return (
    <HoverCard offset={21} width={320} position="bottom-start">
      <HoverCard.Target>{children}</HoverCard.Target>
      <HoverCard.Dropdown data-testid="supporter-hover-card">
        {title && <Text>{title}</Text>}
        {text && (
          <Text component="div" c={title ? "dimmed" : undefined} fz="sm">
            {text}
          </Text>
        )}
      </HoverCard.Dropdown>
    </HoverCard>
  );
}

/**
 * The topbar's supporter badge, for the app to put next to its home
 * button: a quiet "Become a supporter" without a valid key, else the
 * supporter's name with the heart (an individual) or the
 * organisation's icon (its branding), or that icon alone when its
 * branding hides the name: the name is then the icon's text. A
 * click opens the Mogh supporter page in a new tab, or the link an
 * organization's branding sets.
 *
 * Both have a hover card for the app's own words: `supportedText`
 * under the thanks of a supporter's badge, `unsupportedText` on the
 * offer.
 *
 * Its text gives way where the topbar is short of room: it is cut
 * with an ellipsis before anything next to it is.
 *
 * Renders nothing when the branding puts the brand in place of the
 * app's home button (`replace_home`): the app shows it there, see
 * `useSupporterBrand`.
 */
export function SupporterBadge({
  supporter,
  branding,
  href = SUPPORTER_URL,
  supportedText,
  unsupportedText,
  ...buttonProps
}: SupporterBadgeProps) {
  const brand = useShownSupporterBrand(supporter, branding);
  if (supporter === undefined) {
    return null;
  }
  const heart = <Heart size="1rem" />;
  if (supporter === null) {
    const offer = (
      <Button
        component="a"
        href={href}
        target="_blank"
        rel="noopener noreferrer"
        // Quiet: an offer, next to the app's own name.
        variant="subtle"
        c="dimmed"
        miw={0}
        leftSection={heart}
        data-testid="become-supporter"
        {...buttonProps}
      >
        <Text span inherit truncate>
          Become a supporter
        </Text>
      </Button>
    );
    return unsupportedText ? (
      <SupporterHoverCard text={unsupportedText}>{offer}</SupporterHoverCard>
    ) : (
      offer
    );
  }
  if (brand?.replaceHome) {
    return null;
  }
  const icon = brand ? (
    <SupporterBrandIcon brand={brand} fallback={heart} />
  ) : (
    heart
  );
  return (
    <SupporterHoverCard
      title={supporterThanks(supporter)}
      text={
        typeof supportedText === "function"
          ? supportedText(supporter)
          : supportedText
      }
    >
      <Button
        component="a"
        // The organization's own link, if its branding sets one.
        href={brand?.link ?? href}
        target="_blank"
        rel="noopener noreferrer"
        variant="subtle"
        color="gray"
        miw={0}
        // Room for an icon higher than the button.
        h={Math.max(
          BADGE_HEIGHT,
          (brand?.icon ? supporterIconHeight(brand) : 0) + 4,
        )}
        px={brand?.hideName ? "xs" : undefined}
        leftSection={brand?.hideName ? undefined : icon}
        data-testid="supporter-badge"
        aria-label={`${supporter.name}, supporter`}
        {...buttonProps}
      >
        {brand?.hideName ? (
          // The icon alone: it includes the name.
          icon
        ) : (
          <Text
            span
            inherit
            truncate
            // In capitals when an organization's branding says so.
            tt={brand?.uppercaseName ? "uppercase" : undefined}
          >
            {supporter.name}
          </Text>
        )}
      </Button>
    </SupporterHoverCard>
  );
}

/** Main content shown on hover. */
export function supporterThanks({ tier }: Supporter): string {
  switch (tier) {
    case "individual":
      return `Individual supporter`;
    case "organization":
      return `Organization supporter`;
    case "sponsor":
      return `Sponsor`;
  }
}
