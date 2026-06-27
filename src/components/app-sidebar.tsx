import * as React from "react"

import { NavMain } from "@/components/nav-main"
import { NavSecondary } from "@/components/nav-secondary"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"
import {
  CircleHelpIcon,
  FileSearchIcon,
  FolderSearchIcon,
  Settings2Icon,
  ShieldIcon,
} from "lucide-react"

export type AppSection = "scan" | "compromise" | "settings"

const data = {
  navMain: [
    {
      title: "Scan",
      section: "scan" satisfies AppSection,
      icon: <FileSearchIcon />,
    },
    {
      title: "Compromise Check",
      section: "compromise" satisfies AppSection,
      icon: <FolderSearchIcon />,
    },
  ],
  navSecondary: [
    {
      title: "Settings",
      section: "settings" satisfies AppSection,
      icon: <Settings2Icon />,
    },
    {
      title: "Report-only",
      section: "settings" satisfies AppSection,
      icon: <CircleHelpIcon />,
    },
  ],
}

export function AppSidebar({
  activeSection,
  onSectionChange,
  ...props
}: React.ComponentProps<typeof Sidebar> & {
  activeSection: AppSection
  onSectionChange: (section: AppSection) => void
}) {
  const handleSectionChange = (section: string) => {
    onSectionChange(section as AppSection)
  }

  return (
    <Sidebar collapsible="offcanvas" {...props}>
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              className="data-[slot=sidebar-menu-button]:p-1.5!"
              onClick={() => onSectionChange("scan")}
            >
              <ShieldIcon className="size-5!" />
              <span className="text-base font-semibold">Virus Scanner</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        <NavMain
          items={data.navMain}
          activeSection={activeSection}
          onSectionChange={handleSectionChange}
        />
        <NavSecondary
          items={data.navSecondary}
          activeSection={activeSection}
          onSectionChange={handleSectionChange}
          className="mt-auto"
        />
      </SidebarContent>
      <SidebarFooter />
    </Sidebar>
  )
}
