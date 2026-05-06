import { TextInput, TextInputProps } from "@mantine/core";
import { Search } from "lucide-react";

export interface SearchInputProps extends TextInputProps {
  onSearch?: (search: string) => void;
}

export function SearchInput({
  onSearch,
  onChange,
  ...inputProps
}: SearchInputProps) {
  return (
    <TextInput
      placeholder="search..."
      leftSection={<Search size="0.8rem" />}
      w={{ base: "100%", xs: 220 }}
      onChange={(e) => {
        onChange?.(e);
        onSearch?.(e.target.value);
      }}
      onClick={(e) => e.stopPropagation()}
      {...inputProps}
    />
  );
}
