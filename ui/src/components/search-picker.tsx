import {
  ActionIcon,
  ButtonProps,
  Combobox,
  ComboboxProps,
  ComboboxStore,
  Group,
} from "@mantine/core";
import { ChevronsUpDown, Search, X } from "lucide-react";
import { ReactNode, useEffect } from "react";

/** The search state of a picker, from `useSearchCombobox`. */
export interface PickerSearch {
  search: string;
  setSearch: (search: string) => void;
  combobox: ComboboxStore;
}

export interface SearchPickerProps extends Omit<ComboboxProps, "store"> {
  /**
   * Its search (`useSearchCombobox()`): the caller filters its options
   * by `search`, in the browser or in the query it sends.
   */
  picker: PickerSearch;
  /** The button opening it (eg. with `pickerTargetProps`). */
  target: ReactNode;
  /** The options (`Combobox.Option`s). */
  children: ReactNode;
  /** Shows `emptyText` under the options. */
  empty?: boolean;
  emptyText?: string;
  /** Also the search input's accessible name. Default "Search". */
  searchPlaceholder?: string;
  /**
   * A clear button next to the target: a button of its own (a keyboard
   * target with a name), not an element inside the target button.
   */
  onClear?: () => void;
  /** Whether there is something to clear. */
  canClear?: boolean;
  /** The clear button's accessible name. Default "Clear". */
  clearLabel?: string;
}

/**
 * A searchable picker: a target button, and a dropdown with a search
 * input over the options, as Komodo's pickers had it (13 of them,
 * written out each time and drifting apart).
 */
export function SearchPicker({
  picker: { search, setSearch, combobox },
  target,
  children,
  empty,
  emptyText = "No results.",
  searchPlaceholder = "Search",
  onClear,
  canClear,
  clearLabel = "Clear",
  width = 300,
  position = "bottom-start",
  ...comboboxProps
}: SearchPickerProps) {
  const picker = (
    <Combobox
      store={combobox}
      width={width}
      position={position}
      {...comboboxProps}
    >
      <Combobox.Target>{target}</Combobox.Target>
      <Combobox.Dropdown>
        <Combobox.Search
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          leftSection={<Search size="1rem" />}
          placeholder={searchPlaceholder}
          aria-label={searchPlaceholder}
        />
        <Combobox.Options mah={224} style={{ overflowY: "auto" }}>
          {children}
          {empty && <Combobox.Empty>{emptyText}</Combobox.Empty>}
        </Combobox.Options>
      </Combobox.Dropdown>
    </Combobox>
  );
  if (!onClear) return picker;
  return (
    <Group gap={4} wrap="nowrap" maw="100%">
      {picker}
      <ActionIcon
        size="sm"
        variant="filled"
        color="red"
        onClick={onClear}
        disabled={comboboxProps.disabled || !canClear}
        aria-label={clearLabel}
      >
        <X size="0.8rem" />
      </ActionIcon>
    </Group>
  );
}

/** The usual target of a picker showing its pick: opens the dropdown. */
export function pickerTargetProps(combobox: ComboboxStore): ButtonProps & {
  onClick: () => void;
} {
  return {
    justify: "space-between",
    rightSection: <ChevronsUpDown size="1rem" />,
    onClick: () => combobox.toggleDropdown(),
  };
}

/**
 * Picks the first option once the options load (or their first one
 * changes) while nothing is picked, unless the picker can be cleared
 * (where nothing is a choice).
 */
export function usePickFirst(
  first: string | undefined,
  selected: string | undefined,
  onSelect: ((value: string) => void) | undefined,
  clearable: boolean | undefined,
) {
  useEffect(() => {
    if (!clearable && first && !selected) onSelect?.(first);
    // Only when the first option changes, reading `selected` and
    // `onSelect` (often an inline callback) at that time.
  }, [first]);
}
