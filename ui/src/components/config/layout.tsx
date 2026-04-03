import { ReactNode } from "react";
import { Section, SectionProps } from "../section";
import { Settings } from "lucide-react";

/** Includes save buttons */
export function ConfigLayout({
  title,
  icon,
  titleOther,
  SaveOrReset,
  ...sectionProps
}: {
  SaveOrReset: ReactNode | undefined;
} & SectionProps) {
  const titleProps = titleOther
    ? { titleOther }
    : {
        title: title ?? "Config",
        icon: icon ?? <Settings size="1rem" />,
      };
  return <Section actions={SaveOrReset} gap="md" {...titleProps} {...sectionProps} />;
}
