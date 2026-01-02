import { CircleCheckBig, Moon, Sun } from "lucide-solid";
import {
  createContext,
  createEffect,
  createSignal,
  JSX,
  useContext,
} from "solid-js";
import { DropdownMenu } from "@kobalte/core/dropdown-menu";
import { cn } from "./utils";
import { buttonVariants } from "./components/button";

type Theme = "dark" | "light" | "system";

type ThemeProviderProps = {
  children: JSX.Element;
  defaultTheme?: Theme;
  storageKey?: string;
};

type ThemeProviderState = {
  theme: () => Theme;
  currentTheme: () => Exclude<Theme, "system">;
  setTheme: (theme: Theme) => void;
};

const initialState: ThemeProviderState = {
  theme: () => "system",
  currentTheme: () => "dark",
  setTheme: () => null,
};

const DEFAULT_STORAGE_KEY = "ui-theme-v1";

const ThemeProviderContext = createContext<ThemeProviderState>(initialState);

const systemTheme = () =>
  window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";

export function ThemeProvider(props: ThemeProviderProps) {
  const [theme, setTheme] = createSignal<Theme>(
    ((localStorage.getItem(props.storageKey ?? DEFAULT_STORAGE_KEY) as Theme) ||
      props.defaultTheme) ??
      "system"
  );
  // Tracks the current theme
  //   - if theme is light or dark, equal to theme.
  //   - if theme is system, tracks current theme with pool loop
  const [currentTheme, setCurrentTheme] = createSignal<
    Exclude<Theme, "system">
  >(
    theme() === "system" ? systemTheme() : (theme() as Exclude<Theme, "system">)
  );

  createEffect((prev?: () => void) => {
    prev?.();
    if (theme() === "system") {
      setCurrentTheme(systemTheme());
      // For 'system' theme, need to poll
      // matchMedia for update to theme.
      const interval = setInterval(() => {
        setCurrentTheme(systemTheme());
      }, 5_000);
      return () => clearInterval(interval);
    } else {
      setCurrentTheme(theme() as Exclude<Theme, "system">);
    }
  });

  createEffect((prev?: () => void) => {
    prev?.();
    const root = window.document.documentElement;
    // instantiate it to lock this val into this closure
    const theme = currentTheme();
    root.classList.add(theme);
    return () => root.classList.remove(theme);
  });

  return (
    <ThemeProviderContext.Provider
      {...props}
      value={{
        theme,
        currentTheme,
        setTheme: (theme: Theme) => {
          localStorage.setItem(props.storageKey ?? DEFAULT_STORAGE_KEY, theme);
          setTheme(theme);
        },
      }}
    >
      {props.children}
    </ThemeProviderContext.Provider>
  );
}

export const useTheme = () => {
  const context = useContext(ThemeProviderContext);

  if (context === undefined)
    throw new Error("useTheme must be used within a ThemeProvider");

  return context;
};

export function ThemeToggle() {
  const { theme, setTheme } = useTheme();

  return (
    <DropdownMenu>
      <DropdownMenu.Trigger
        class={cn(
          buttonVariants({
            variant: "ghost",
          })
        )}
      >
        <Sun class="w-4 h-4 rotate-0 scale-100 transition-all dark:-rotate-90 dark:scale-0" />
        <Moon class="absolute w-4 h-4 rotate-90 scale-0 transition-all dark:rotate-0 dark:scale-100" />
        <span class="sr-only">Toggle theme</span>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content class="z-50">
          <DropdownMenu.Item
            class="cursor-pointer flex items-center justify-between gap-2"
            onClick={() => {
              setTheme("light");
            }}
          >
            Light
            {theme() === "light" && <CircleCheckBig class="w-3 h-3" />}
          </DropdownMenu.Item>
          <DropdownMenu.Item
            class="cursor-pointer flex items-center justify-between gap-2"
            onClick={() => setTheme("dark")}
          >
            Dark
            {theme() === "dark" && <CircleCheckBig class="w-3 h-3" />}
          </DropdownMenu.Item>
          <DropdownMenu.Item
            class="cursor-pointer flex items-center justify-between gap-2"
            onClick={() => setTheme("system")}
          >
            System
            {theme() === "system" && <CircleCheckBig class="w-3 h-3" />}
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu>
  );
}
