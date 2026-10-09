import {
  Dispatch,
  SetStateAction,
  useCallback,
  useState,
  useSyncExternalStore,
} from "react";
import {
  Alert,
  Anchor,
  Badge,
  Button,
  Code,
  FileButton,
  Group,
  NumberInput,
  Stack,
  Text,
  Textarea,
  TextInput,
} from "@mantine/core";
import { notifications } from "@mantine/notifications";
import {
  QueryState,
  useMutation,
  UseMutationOptions,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import {
  Heart,
  Palette,
  Save,
  ShieldAlert,
  Trash,
  Upload,
  X,
} from "lucide-react";
import * as MoghAuth from "mogh_auth_client";
import {
  brandingIconProblem,
  brandingLinkProblem,
  brandingProblem,
  brandingSizeProblem,
  checkSupporterKey,
  DEFAULT_ICON_HEIGHT,
  ICON_MEDIA_TYPES,
  iconDataUrl,
  MAX_ICON_BYTES,
  MAX_ICON_HEIGHT,
  MAX_ICON_WIDTH,
  MIN_ICON_SIZE,
  MoghSupporterClient,
  newNonce,
  normalizeBranding,
  SUPPORTER_URL,
  SupporterKeyError,
} from "mogh_supporter";
import type {
  Supporter,
  SupporterWriteResponses,
  Types,
  VerifySupporterKeyOptions,
} from "mogh_supporter";
import { sendWithJwt, useSendableJwt } from "../auth/rejected-jwt";
import { errorNotificationMessage } from "../errors";
import {
  Config,
  ConfigInput,
  ConfigItem,
  ConfigSwitch,
} from "../components/config";
import { ConfirmButton } from "../components/confirm-button";
import { EnableSwitch } from "../components/enable-switch";
import { Section, SectionProps } from "../components/section";
import { SupporterBrandIcon, useShownSupporterBrand } from "./badge";

export * from "./badge";
export * from "./home-button";

export let SUPPORTER_API_URL: string;

/**
 * Set the url the app serves the supporter api at (`mogh_supporter`'s
 * `server::router`, eg. `https://app.example/supporter`). Call it
 * before the first render, like `setAuthUrl`: `useSupporter` and
 * `SupporterKeyConfig` talk to the api on their own.
 */
export function setSupporterUrl(url: string) {
  SUPPORTER_API_URL = url;
}

/**
 * A client of the supporter api, with the user's current token (or
 * `jwt`).
 */
export function supporterClient(jwt = MoghAuth.LOGIN_TOKENS.jwt()) {
  return MoghSupporterClient(SUPPORTER_API_URL, jwt);
}

export interface UseSupporterOptions extends Omit<
  VerifySupporterKeyOptions,
  "nonce" | "response"
> {
  /** Default `true`. Eg. only once the user is logged in. */
  enabled?: boolean;
}

/**
 * What the page's verification of the key in use (`useSupporter`)
 * found: the supporter to show a badge for, else `null` and why there
 * is none, which `SupporterKeyConfig` shows the admin.
 */
interface SupporterVerdict {
  supporter: Supporter | null;
  /** Why there is no badge. `null` with a supporter. */
  reason: string | null;
}

/** The query of the page's verification, by app (`useSupporter`). */
const SUPPORTER_QUERY = "mogh_supporter";

/**
 * The supporter to show a badge for (`SupporterBadge`): `undefined`
 * while the key is being verified, `null` for no badge. Asks the
 * supporter api for the key in use with a nonce drawn for the
 * request, and verifies the answer in the browser (`mogh_supporter`),
 * once per page load: the result is kept in memory by react-query for
 * the life of the page, never in storage. `SupporterKeyConfig`
 * invalidates it when the key changes, and shows the admin why it
 * shows no badge (eg. a release date past what the key covers). A page
 * without WebCrypto (plain http from another host than localhost)
 * verifies all the same: `mogh_supporter` 1.2 falls back to
 * JavaScript there.
 *
 * Pass `app`, `releaseDate` (the `YYYY-MM-DD` of the release, the
 * `releaseDate` of the app's package.json through `mogh_supporter/vite`,
 * never the current date) and `rootKeys`, the root public keys the app
 * trusts: each app hardcodes its own. `revoked` is the package's unless
 * the app has its own list.
 */
export function useSupporter({
  enabled = true,
  ...verify
}: UseSupporterOptions): Supporter | null | undefined {
  const jwt = useSendableJwt();
  const { data } = useQuery({
    queryKey: [SUPPORTER_QUERY, verify.app],
    queryFn: async (): Promise<SupporterVerdict> => {
      const nonce = newNonce();
      let response: Types.SignedSupporterKey | null;
      try {
        response = await sendWithJwt([401, 403], (jwt) =>
          supporterClient(jwt).read("GetSupporterKey", {
            nonce: nonce.encoded,
          }),
        );
      } catch (e) {
        console.debug("No supporter badge: GetSupporterKey failed:", e);
        const error = (e as { result?: { error?: unknown } })?.result?.error;
        return {
          supporter: null,
          reason: `GetSupporterKey failed${typeof error === "string" ? `: ${error}` : ""}`,
        };
      }
      try {
        const supporter = await checkSupporterKey({
          ...verify,
          nonce,
          response,
        });
        return { supporter, reason: null };
      } catch (e) {
        console.debug(
          "No supporter badge:",
          e instanceof Error ? `${e.name}: ${e.message}` : e,
        );
        return {
          supporter: null,
          reason:
            e instanceof SupporterKeyError
              ? e.message
              : e instanceof Error
                ? `${e.name}: ${e.message}`
                : String(e),
        };
      }
    },
    enabled: enabled && !!jwt,
    staleTime: Infinity,
    gcTime: Infinity,
    retry: false,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
    refetchOnMount: false,
  });
  return data?.supporter;
}

/**
 * The state of the page's verification of the key in use, as
 * `useSupporter` (the topbar's badge) runs it, without running one:
 * what this browser makes of the key, which may not be what the server
 * makes of it. `undefined` while none ran.
 */
function useSupporterVerdict(): QueryState<SupporterVerdict> | undefined {
  const queryClient = useQueryClient();
  const subscribe = useCallback(
    (onChange: () => void) => queryClient.getQueryCache().subscribe(onChange),
    [queryClient],
  );
  // The state object is replaced on every change of the query, and
  // kept otherwise: a snapshot which changes only with it.
  return useSyncExternalStore(
    subscribe,
    () =>
      queryClient.getQueryCache().findAll({ queryKey: [SUPPORTER_QUERY] })[0]
        ?.state as QueryState<SupporterVerdict> | undefined,
  );
}

/**
 * How the badge of an organization or sponsor is shown, as admins set
 * it (`SupporterKeyConfig`): its icon, the icon's size, and whether it
 * takes the place of the app's home button. For every user, kept for
 * the life of the page.
 */
export function useSupporterBranding(options?: { enabled?: boolean }) {
  const jwt = useSendableJwt();
  return useQuery({
    queryKey: ["GetSupporterBranding"],
    queryFn: () =>
      sendWithJwt([401, 403], (jwt) =>
        supporterClient(jwt).read("GetSupporterBranding", {}),
      ),
    enabled: (options?.enabled ?? true) && !!jwt,
    staleTime: Infinity,
    retry: false,
    refetchOnWindowFocus: false,
  });
}

/**
 * Everything the topbar shows of the supporter key: `supporter` (see
 * `useSupporter`) and `branding` for `SupporterBadge`, and the
 * `brand` of a verified organization's or sponsor's key.
 *
 * `homeBrand` is that brand when its branding puts it in place of the
 * app's home button, else `null`. The app then shows the brand's icon
 * (`SupporterBrandIcon`, the app's own logo while none is set) and
 * name there, still leading to `/`, and `SupporterBadge` renders
 * nothing. While `homeBrand.hideName` is set the icon stands alone,
 * without the name: it is only ever set with an icon, and not while
 * the icon fails to load.
 */
export function useSupporterBrand(options: UseSupporterOptions) {
  const supporter = useSupporter(options);
  const branding = useSupporterBranding({ enabled: options.enabled }).data;
  const brand = useShownSupporterBrand(supporter, branding);
  return {
    supporter,
    branding,
    brand,
    homeBrand: brand?.replaceHome ? brand : null,
  };
}

/**
 * What is configured, for `SupporterKeyConfig`: the supporter the key
 * in use names, where the key comes from, and whether it would show a
 * badge. Never the key itself. Admin only.
 */
export function useSupporterKeyInfo(options?: { enabled?: boolean }) {
  const jwt = useSendableJwt();
  return useQuery({
    queryKey: ["GetSupporterKeyInfo"],
    queryFn: () =>
      sendWithJwt([401], (jwt) =>
        supporterClient(jwt).read("GetSupporterKeyInfo", {}),
      ),
    enabled: (options?.enabled ?? true) && !!jwt,
    // A user who isn't an admin gets the same answer every time.
    retry: false,
  });
}

/** What a failed supporter request rejects with. */
type SupporterError = { result?: { error?: string; trace?: string[] } };

/**
 * The write api of the supporter key (`SetSupporterKey`,
 * `DeleteSupporterKey`), admin only, with an error notification.
 */
export function useManageSupporter<
  T extends Types.SupporterWriteRequest["type"],
  R extends Extract<Types.SupporterWriteRequest, { type: T }>,
  P extends R["params"],
  C extends Omit<
    UseMutationOptions<SupporterWriteResponses[T], unknown, P, unknown>,
    "mutationKey" | "mutationFn"
  >,
>(type: T, config?: C) {
  return useMutation({
    // Spread first: a caller's `onError` extends the notification.
    ...config,
    mutationKey: [type],
    mutationFn: (params: P) => supporterClient().write<T, R>(type, params),
    onError: (e: SupporterError, ...args) => {
      console.log("Supporter error:", e);
      notifications.show({
        title: `Supporter request ${type} failed`,
        message: errorNotificationMessage(e),
        color: "red",
      });
      config?.onError && config.onError(e, ...args);
    },
  });
}

/**
 * Manage the app's supporter key: what is configured, a field to
 * paste a new key into, and its removal. For an app's settings page,
 * wherever makes sense. The key is used right away: the topbar badge
 * (`useSupporter`) verifies it again without a reload.
 *
 * With the key of an organization or sponsor it also manages the
 * branding: the icon in place of the heart (a url or an uploaded
 * image), its size, and whether icon and name take the place of the
 * app's home button.
 *
 * The api behind it is limited to admin users, see
 * `AuthUserImpl::is_admin`. A key from the app configuration is
 * shown, and replaced by one saved here until that is removed.
 *
 * Next to the server's verdict on the key it shows this browser's,
 * from the page's own verification (`useSupporter`, the topbar's
 * badge): a key the server verifies and serves can still show no
 * badge here, eg. for a release date past what the key covers, which
 * only the browser knows.
 */
export function SupporterKeyConfig(sectionProps: SectionProps) {
  const queryClient = useQueryClient();
  const { data: info, isPending, error } = useSupporterKeyInfo();
  const verdict = useSupporterVerdict();
  // Not while the key changes: an invalidated verdict is of the key
  // before.
  const browser =
    verdict?.fetchStatus === "idle" && !verdict.isInvalidated
      ? verdict.data
      : undefined;
  const [key, setKey] = useState("");

  const invalidate = () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: ["GetSupporterKeyInfo"] }),
      // The topbar badge verifies the key in use again.
      queryClient.invalidateQueries({ queryKey: [SUPPORTER_QUERY] }),
    ]);
  const { mutateAsync: set, isPending: setPending } = useManageSupporter(
    "SetSupporterKey",
    {
      onSuccess: () => {
        setKey("");
        notifications.show({ message: "Supporter key saved." });
        invalidate();
      },
    },
  );
  const { mutate: remove, isPending: removePending } = useManageSupporter(
    "DeleteSupporterKey",
    {
      onSuccess: () => {
        notifications.show({ message: "Supporter key removed." });
        invalidate();
      },
    },
  );

  return (
    <Stack gap="xl">
      <Section
        title="Supporter Key"
        titleFz="h3"
        icon={<Heart size="1.2rem" />}
        description={
          <>
            Shows a supporter badge in the topbar. Keys are issued by email and
            verified offline via cryptographic signature.{" "}
            <Anchor
              href={SUPPORTER_URL}
              target="_blank"
              rel="noopener noreferrer"
              // Readable in every theme: the text's color, underlined.
              c="inherit"
              underline="always"
            >
              {info?.supporter ? "Learn more" : "Become a supporter"}
            </Anchor>
          </>
        }
        isPending={isPending}
        error={
          error
            ? (((error as any)?.result?.error as string | undefined) ??
              "Failed to load the supporter key")
            : false
        }
        data-testid="supporter-key-config"
        {...sectionProps}
      >
        <Stack gap="xl" mt="md">
          {info && <SupporterKeyStatus info={info} browser={browser} />}
          <Textarea
            label="Supporter key"
            description="Paste the key you received. It is stored by the app and used from now on. The key itself is never shown again."
            placeholder="xxxx.xxxx.xxxx"
            value={key}
            onChange={(e) => setKey(e.currentTarget.value)}
            autosize
            minRows={3}
            maxRows={6}
            spellCheck={false}
            autoComplete="off"
            styles={{
              input: {
                fontFamily: "monospace",
                fontSize: "var(--mantine-font-size-xs)",
                wordBreak: "break-all",
              },
            }}
            maw={960}
          />
          <Group>
            <Button
              leftSection={<Save size="1rem" />}
              disabled={!key.trim()}
              loading={setPending}
              onClick={() => set({ key }).catch(() => {})}
            >
              Save
            </Button>
            {info?.source === "Stored" && (
              <ConfirmButton
                variant="default"
                icon={<Trash size="1rem" />}
                loading={removePending}
                onClick={() => remove({})}
                w="fit-content"
                confirmProps={{ color: "red", variant: "filled" }}
              >
                Remove
              </ConfirmButton>
            )}
          </Group>
        </Stack>
      </Section>
      {/* The branding of a key the server verified: another one is
          not served, and brands nothing. */}
      {info?.supporter &&
        !info.problem &&
        info.supporter.tier !== "individual" && (
          <SupporterBrandingConfig
            name={info.supporter.name}
            titleFz={sectionProps.titleFz ?? "h3"}
            withBorder={sectionProps.withBorder}
          />
        )}
    </Stack>
  );
}

/**
 * The branding as the config form holds it: every field set, so the
 * `Config` can tell what changed.
 */
interface BrandingForm {
  /**
   * An image url or a path, the label of an uploaded image
   * (`uploadLabel`), or empty for none.
   */
  icon: string;
  /** Pixels as typed, or empty: as the image is at the height. */
  icon_width: string;
  /** Pixels as typed, or empty: `DEFAULT_ICON_HEIGHT`. */
  icon_height: string;
  /** A web address, or empty: the Mogh supporter page. */
  link: string;
  hide_name: boolean;
  uppercase_name: boolean;
  replace_home: boolean;
}

/**
 * How an uploaded icon reads in the form and in its confirm dialog:
 * the image itself, a `data:` url, is no text to show.
 */
function uploadLabel(icon: string, name = "Uploaded image") {
  const type = icon
    .slice("data:image/".length, icon.indexOf(";"))
    .replace("+xml", "");
  const bytes = Math.floor(((icon.length - icon.indexOf(",") - 1) * 3) / 4);
  return `${name} (${type}, ${Math.max(1, Math.round(bytes / 1024))} KB)`;
}

/**
 * The branding of an organization's or sponsor's key, as
 * `SupporterKeyConfig` edits it: a `Config` with the icon (a url or
 * an upload), its size, and the switches to show the icon alone,
 * without the name, and to use it as the home button, with a
 * preview. Saved whole, after the `Config`'s confirm dialog.
 */
function SupporterBrandingConfig({
  name,
  ...sectionProps
}: { name: string } & SectionProps) {
  const queryClient = useQueryClient();
  const { data: stored } = useSupporterBranding();
  const kept = normalizeBranding(stored);
  // The images uploaded here, by their labels: the form holds the
  // label, the save sends the image.
  const [uploads, setUploads] = useState<Record<string, string>>({});
  const keptUpload = kept.icon?.startsWith("data:")
    ? uploadLabel(kept.icon)
    : undefined;
  const isUpload = (icon: string) => icon in uploads || icon === keptUpload;
  const iconOf = (icon: string) =>
    uploads[icon] ?? (icon === keptUpload ? kept.icon : icon);

  const original: BrandingForm = {
    icon: keptUpload ?? kept.icon ?? "",
    icon_width: kept.icon_width?.toString() ?? "",
    icon_height: kept.icon_height?.toString() ?? "",
    link: kept.link ?? "",
    hide_name: !!kept.hide_name,
    uppercase_name: !!kept.uppercase_name,
    replace_home: !!kept.replace_home,
  };
  const [update, setRawUpdate] = useState<Partial<BrandingForm>>({});
  // A field set back to what is kept is no change.
  const setUpdate: Dispatch<SetStateAction<Partial<BrandingForm>>> = (action) =>
    setRawUpdate((previous) => {
      const next = typeof action === "function" ? action(previous) : action;
      return Object.fromEntries(
        Object.entries(next).filter(
          ([key, value]) => value !== original[key as keyof BrandingForm],
        ),
      );
    });
  const values = { ...original, ...update };

  const size = (pixels: string) =>
    pixels.trim() === "" ? undefined : Number(pixels);
  const branding = normalizeBranding({
    icon: iconOf(values.icon),
    icon_width: size(values.icon_width),
    icon_height: size(values.icon_height),
    link: values.link,
    hide_name: values.hide_name,
    uppercase_name: values.uppercase_name,
    replace_home: values.replace_home,
  });
  // The name can be hidden behind an icon only.
  const hasIcon = !!branding.icon;
  // The brand as the topbar would show it, with any organization's
  // tier: the tiers show alike.
  const preview = useShownSupporterBrand(
    { name, tier: "organization" } as Supporter,
    branding,
  )!;

  const { mutateAsync: save } = useManageSupporter("SetSupporterBranding", {
    onSuccess: (saved) => {
      notifications.show({ message: "Supporter branding saved." });
      // The form and the topbar show it right away.
      queryClient.setQueryData(["GetSupporterBranding"], saved);
      queryClient.invalidateQueries({ queryKey: ["GetSupporterBranding"] });
    },
  });

  const pixels = (
    dimension: "width" | "height",
    value: string,
    set: (value: string) => void,
  ) => {
    const max = dimension === "width" ? MAX_ICON_WIDTH : MAX_ICON_HEIGHT;
    return (
      <NumberInput
        aria-label={`Icon ${dimension}`}
        placeholder={
          dimension === "width" ? "Auto" : String(DEFAULT_ICON_HEIGHT)
        }
        value={value === "" ? "" : Number(value)}
        onChange={(input) => set(input === "" ? "" : String(input))}
        min={MIN_ICON_SIZE}
        max={max}
        allowDecimal={false}
        allowNegative={false}
        error={brandingSizeProblem(dimension, size(value))}
        w={{ base: "85%", lg: 400 }}
      />
    );
  };

  return (
    <Config
      title="Appearance"
      icon={<Palette size="1.2rem" />}
      original={original}
      update={update}
      setUpdate={setUpdate}
      disabled={false}
      disableSidebar
      onSave={async () => {
        const problem = brandingProblem(branding);
        if (problem) {
          notifications.show({ message: problem, color: "red" });
          throw new Error(problem);
        }
        await save({ branding });
      }}
      data-testid="supporter-branding-config"
      {...sectionProps}
      groups={{
        "": [
          {
            label: "Icon",
            description: `Shown in place of the heart. Accepts an image url or an uploaded image (png, jpeg, gif, webp or svg, up to ${MAX_ICON_BYTES / 1024} KB).`,

            fields: {
              icon: (icon, set) => (
                <ConfigItem>
                  <Group align="flex-start">
                    <TextInput
                      aria-label="Icon"
                      placeholder="https://example.com/logo.png"
                      value={icon}
                      // An uploaded image is replaced or cleared.
                      disabled={isUpload(icon)}
                      onChange={(e) => set({ icon: e.currentTarget.value })}
                      error={
                        icon.trim() && !isUpload(icon)
                          ? brandingIconProblem(icon.trim())
                          : null
                      }
                      w={{ base: "85%", lg: 400 }}
                    />
                    <FileButton
                      accept={ICON_MEDIA_TYPES.join(",")}
                      onChange={(file) => {
                        if (!file) return;
                        iconDataUrl(file)
                          .then((image) => {
                            const label = uploadLabel(image, file.name);
                            setUploads((uploads) => ({
                              ...uploads,
                              [label]: image,
                            }));
                            set({ icon: label });
                          })
                          .catch((e) =>
                            notifications.show({
                              title: "This image can't be the icon",
                              message:
                                e instanceof Error ? e.message : String(e),
                              color: "red",
                            }),
                          );
                      }}
                    >
                      {(props) => (
                        <Button
                          variant="default"
                          leftSection={<Upload size="1rem" />}
                          {...props}
                        >
                          Upload
                        </Button>
                      )}
                    </FileButton>
                    {icon && (
                      <Button
                        variant="default"
                        leftSection={<X size="1rem" />}
                        onClick={() => set({ icon: "" })}
                      >
                        Clear icon
                      </Button>
                    )}
                  </Group>
                  <Group gap="sm">
                    <Text c="dimmed" size="sm">
                      Preview
                    </Text>
                    <Group
                      gap="xs"
                      mih={36}
                      data-testid="supporter-branding-preview"
                    >
                      <SupporterBrandIcon
                        brand={preview}
                        fallback={<Heart size="1rem" />}
                      />
                      {!preview.hideName && (
                        <Text
                          tt={preview.uppercaseName ? "uppercase" : undefined}
                        >
                          {name}
                        </Text>
                      )}
                    </Group>
                  </Group>
                </ConfigItem>
              ),
              icon_height: (height, set) => (
                <ConfigItem
                  label="Height"
                  description={`In pixels. Max of ${MAX_ICON_HEIGHT} px. Default: ${DEFAULT_ICON_HEIGHT} px.`}
                >
                  {pixels("height", height, (icon_height) =>
                    set({ icon_height }),
                  )}
                </ConfigItem>
              ),
              icon_width: (width, set) => (
                <ConfigItem
                  label="Width"
                  description={`In pixels. Max of ${MAX_ICON_WIDTH} px. Default: automatic`}
                >
                  {pixels("width", width, (icon_width) => set({ icon_width }))}
                </ConfigItem>
              ),
            },
          },
          {
            label: "Link",
            labelHidden: true,
            fields: {
              link: (link, set) => (
                <ConfigInput
                  label="Link"
                  description={`Opens in a new tab when the badge is clicked. Default: ${SUPPORTER_URL}`}
                  placeholder="https://example.com"
                  value={link}
                  onValueChange={(link) => set({ link })}
                  inputProps={{
                    // Names the input itself: the item's own label is no `<label>`.
                    "aria-label": "Link",
                    error: link.trim()
                      ? brandingLinkProblem(link.trim())
                      : null,
                  }}
                />
              ),
            },
          },
          {
            label: "Options",
            labelHidden: true,
            fields: {
              uppercase_name: (uppercase, set) => (
                <ConfigSwitch
                  label="All Caps Name"
                  description="Show the name in capital letters, on the badge and as the home button."
                  switchProps={{ "aria-label": "All caps name" }}
                  value={uppercase}
                  onCheckedChange={(uppercase_name) => set({ uppercase_name })}
                  disabled={false}
                />
              ),
              hide_name: (hide, set) => (
                <ConfigSwitch
                  label="Hide The Name"
                  description="Show the icon alone. Requires an icon."
                  switchProps={{ "aria-label": "Hide the name" }}
                  value={hasIcon && hide}
                  onCheckedChange={(hide_name) => set({ hide_name })}
                  disabled={!hasIcon}
                />
              ),
              replace_home: (replace, set) => (
                <ConfigSwitch
                  label="Home Button"
                  description="Show the icon and name in place of the app's own name in the topbar. Not compatible with 'Link' option."
                  switchProps={{ "aria-label": "Use as the home button" }}
                  value={replace}
                  onCheckedChange={(replace_home) => set({ replace_home })}
                  disabled={false}
                />
              ),
            },
          },
        ],
      }}
    />
  );
}

/**
 * What is configured, as `SupporterKeyConfig` shows it, with this
 * browser's verdict on the key (`browser`), if the page verified it.
 */
function SupporterKeyStatus({
  info,
  browser,
}: {
  info: Types.SupporterKeyInfo;
  browser: SupporterVerdict | undefined;
}) {
  const { source, supporter, problem, config_key } = info;
  if (source === "None") {
    return (
      <Text data-testid="supporter-key-status">
        No supporter key
        {config_key
          ? " in use: the key of the app configuration could not be read, see the server log."
          : "."}
      </Text>
    );
  }
  return (
    <Stack gap="xs" data-testid="supporter-key-status">
      <Group gap="sm">
        {supporter ? (
          <>
            <Heart
              size="1rem"
              color="var(--mantine-color-red-6)"
              fill="var(--mantine-color-red-6)"
            />
            <Text fw="bold">{supporter.name}</Text>
            <Badge color="gray" variant="light" tt="capitalize">
              {supporter.tier}
            </Badge>
          </>
        ) : (
          <Text>A key whose payload does not decode.</Text>
        )}
        <Badge
          color={source === "Stored" ? "blue" : "gray"}
          title={
            source === "Stored" ? "Set here" : "From the app configuration"
          }
        >
          {source}
        </Badge>
      </Group>
      {supporter && (
        <Stack gap="0">
          <Text c="dimmed" size="sm">
            Covers releases until <b>{supporter.covers}</b>.
          </Text>
          <Text c="dimmed" size="sm">
            Key id: <b>{supporter.id}</b>.
          </Text>
        </Stack>
      )}
      {source === "Config" && (
        <Text c="dimmed" size="sm">
          Set by the app configuration (<Code>supporter_key</Code>). A key saved
          here is used instead, until it is removed.
        </Text>
      )}
      {source === "Stored" && config_key && (
        <Text c="dimmed" size="sm">
          Removing it goes back to the key of the app configuration.
        </Text>
      )}
      {problem && (
        <Alert
          color="yellow"
          icon={<ShieldAlert size="1rem" />}
          title="This key does not verify, and shows no badge"
        >
          {problem}
        </Alert>
      )}
      {/* The server verifies and serves the key, the browser verifies
          it again, and can still refuse it. */}
      {!problem && supporter && browser?.supporter === null && (
        <Alert
          color="yellow"
          icon={<ShieldAlert size="1rem" />}
          title="This browser does not verify the key, and shows no badge"
          data-testid="supporter-key-browser-problem"
        >
          {browser.reason}
        </Alert>
      )}
    </Stack>
  );
}
