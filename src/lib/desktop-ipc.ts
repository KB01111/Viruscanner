import { Channel, invoke as tauriInvoke } from "@tauri-apps/api/core"
import { open as tauriOpen } from "@tauri-apps/plugin-dialog"

type DialogOptions = Parameters<typeof tauriOpen>[0]
type DialogResult = Awaited<ReturnType<typeof tauriOpen>>

const unavailableMessage =
  "Desktop IPC is available only inside the Tauri app. Start the desktop shell with `bun run tauri dev` to scan local files."

export { Channel }

export function isDesktopIpcAvailable() {
  if (typeof window === "undefined") return false

  const tauriWindow = window as Window &
    typeof globalThis & {
      __TAURI__?: unknown
      __TAURI_INTERNALS__?: unknown
      __TAURI_IPC__?: unknown
    }

  return Boolean(
    tauriWindow.__TAURI__ ||
      tauriWindow.__TAURI_INTERNALS__ ||
      tauriWindow.__TAURI_IPC__
  )
}

export function desktopIpcUnavailableMessage() {
  return unavailableMessage
}

export async function invokeCommand<T>(
  command: string,
  args?: Record<string, unknown>
) {
  if (!isDesktopIpcAvailable()) {
    throw new Error(unavailableMessage)
  }

  return tauriInvoke<T>(command, args)
}

export async function openDesktopDialog(
  options: DialogOptions
): Promise<DialogResult> {
  if (!isDesktopIpcAvailable()) {
    throw new Error(unavailableMessage)
  }

  return tauriOpen(options)
}
