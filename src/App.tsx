import type { CSSProperties, ReactNode } from "react"
import { useEffect, useMemo, useState } from "react"
import {
  AlertTriangleIcon,
  ArchiveIcon,
  CheckCircle2Icon,
  CloudIcon,
  FileIcon,
  FilePlusIcon,
  FolderOpenIcon,
  FolderSearchIcon,
  HardDriveIcon,
  PlayIcon,
  RotateCcwIcon,
  SearchIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  SquareIcon,
  Trash2Icon,
} from "lucide-react"

import type { CloudStatus } from "@/bindings/CloudStatus"
import type { CloudVerdict } from "@/bindings/CloudVerdict"
import type { CompromiseCheckSuite } from "@/bindings/CompromiseCheckSuite"
import type { CompromiseTarget } from "@/bindings/CompromiseTarget"
import type { EngineStatus } from "@/bindings/EngineStatus"
import type { Finding } from "@/bindings/Finding"
import type { ScanEvent } from "@/bindings/ScanEvent"
import type { ScanFileResult } from "@/bindings/ScanFileResult"
import type { ScanOptions } from "@/bindings/ScanOptions"
import type { ScanSummary } from "@/bindings/ScanSummary"
import type { ScanVerdict } from "@/bindings/ScanVerdict"
import type { StartScanResponse } from "@/bindings/StartScanResponse"
import { AppSidebar, type AppSection } from "@/components/app-sidebar"
import { SiteHeader } from "@/components/site-header"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  SidebarInset,
  SidebarProvider,
} from "@/components/ui/sidebar"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { TooltipProvider } from "@/components/ui/tooltip"
import {
  Channel,
  desktopIpcUnavailableMessage,
  invokeCommand,
  isDesktopIpcAvailable,
  openDesktopDialog,
} from "@/lib/desktop-ipc"

const defaultOptions: ScanOptions = {
  includeArchives: true,
  cloudLookup: false,
  maxFileMb: 64,
  maxArchiveDepth: 2,
}

const emptySummary: ScanSummary = {
  filesSeen: 0,
  filesScanned: 0,
  findings: 0,
  skipped: 0,
  errors: 0,
  canceled: false,
}

const unavailableCloudStatus: CloudStatus = {
  enabled: false,
  provider: "virustotal",
  reason: desktopIpcUnavailableMessage(),
}

const unavailableEngineStatus: EngineStatus = {
  builtInYaraSources: 0,
  externalYaraSources: 0,
  hashIndicators: 0,
  magikaAvailable: false,
  magikaError: desktopIpcUnavailableMessage(),
  signatureSources: [],
  loadErrors: [desktopIpcUnavailableMessage()],
}

const unavailableCompromiseSuite: CompromiseCheckSuite = {
  reportOnly: true,
  groups: [],
  targets: [],
  nextActions: [
    "Open the Tauri desktop shell to load local compromise-check targets.",
  ],
}

const sectionTitles: Record<AppSection, string> = {
  scan: "Scan Workspace",
  compromise: "Compromise Check",
  settings: "Settings",
}

function normalizeDialogResult(result: string | string[] | null): string[] {
  if (!result) return []
  return Array.isArray(result) ? result : [result]
}

function uniqueTargets(current: string[], incoming: string[]) {
  return Array.from(new Set([...current, ...incoming.filter(Boolean)]))
}

function formatBytes(bytes: number) {
  if (bytes === 0) return "0 B"
  const units = ["B", "KB", "MB", "GB", "TB"]
  const index = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1024)),
    units.length - 1
  )
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${units[index]}`
}

function verdictVariant(verdict: ScanVerdict | CloudVerdict) {
  if (verdict === "malicious" || verdict === "error") return "destructive"
  if (verdict === "suspicious" || verdict === "unknown") return "outline"
  if (verdict === "skipped" || verdict === "disabled") return "secondary"
  return "default"
}

function labelize(value: string) {
  return value.replace(/([A-Z])/g, " $1").replace(/^./, (c) => c.toUpperCase())
}

function formatScore(score: number) {
  return `${Math.round(score)}/100`
}

function clampNumber(value: number, min: number, max: number) {
  if (Number.isNaN(value)) return min
  return Math.min(max, Math.max(min, value))
}

function messageFromError(err: unknown) {
  return err instanceof Error ? err.message : String(err)
}

export default function App() {
  const desktopIpcAvailable = isDesktopIpcAvailable()
  const [activeSection, setActiveSection] = useState<AppSection>("scan")
  const [targets, setTargets] = useState<string[]>([])
  const [targetInput, setTargetInput] = useState("")
  const [options, setOptions] = useState<ScanOptions>(defaultOptions)
  const [cloudStatus, setCloudStatus] = useState<CloudStatus | null>(
    desktopIpcAvailable ? null : unavailableCloudStatus
  )
  const [engineStatus, setEngineStatus] = useState<EngineStatus | null>(
    desktopIpcAvailable ? null : unavailableEngineStatus
  )
  const [suite, setSuite] = useState<CompromiseCheckSuite | null>(
    desktopIpcAvailable ? null : unavailableCompromiseSuite
  )
  const [selectedSuiteTargetIds, setSelectedSuiteTargetIds] = useState<Set<string>>(
    () => new Set()
  )
  const [scanId, setScanId] = useState<string | null>(null)
  const [isScanning, setIsScanning] = useState(false)
  const [currentPath, setCurrentPath] = useState("")
  const [results, setResults] = useState<ScanFileResult[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [summary, setSummary] = useState<ScanSummary>(emptySummary)
  const [selectedPath, setSelectedPath] = useState<string | null>(null)
  const [events, setEvents] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!desktopIpcAvailable) {
      setCloudStatus(unavailableCloudStatus)
      setEngineStatus(unavailableEngineStatus)
      setSuite(unavailableCompromiseSuite)
      return
    }

    invokeCommand<CloudStatus>("get_cloud_status")
      .then(setCloudStatus)
      .catch((err) =>
        setCloudStatus({
          enabled: false,
          provider: "virustotal",
          reason: messageFromError(err),
        })
      )
    invokeCommand<EngineStatus>("get_engine_status")
      .then(setEngineStatus)
      .catch((err) =>
        setEngineStatus({
          builtInYaraSources: 0,
          externalYaraSources: 0,
          hashIndicators: 0,
          magikaAvailable: false,
          magikaError: messageFromError(err),
          signatureSources: [],
          loadErrors: [messageFromError(err)],
        })
      )
    invokeCommand<CompromiseCheckSuite>("get_compromise_check_suite")
      .then((response) => {
        setSuite(response)
        setSelectedSuiteTargetIds(
          new Set(
            response.targets
              .filter((target) => target.recommended)
              .map((target) => target.id)
          )
        )
      })
      .catch((err) => {
        setError(messageFromError(err))
      })
  }, [desktopIpcAvailable])

  const selectedResult = useMemo(
    () => results.find((result) => result.path === selectedPath) ?? results[0],
    [results, selectedPath]
  )

  const selectedSuiteTargets = useMemo(() => {
    if (!suite) return []
    return suite.targets.filter(
      (target) => selectedSuiteTargetIds.has(target.id) && target.recommended
    )
  }, [selectedSuiteTargetIds, suite])

  const suspiciousResultCount = useMemo(
    () =>
      results.filter((result) =>
        ["suspicious", "malicious", "error"].includes(result.verdict)
      ).length,
    [results]
  )

  const addManualTarget = () => {
    if (isScanning || !targetInput.trim()) return
    const trimmed = targetInput.trim()
    setTargets((current) => uniqueTargets(current, [trimmed]))
    setTargetInput("")
  }

  const pickFiles = async () => {
    try {
      const result = await openDesktopDialog({
        multiple: true,
        directory: false,
        title: "Select files",
      })
      setTargets((current) => uniqueTargets(current, normalizeDialogResult(result)))
    } catch (err) {
      setError(messageFromError(err))
    }
  }

  const pickFolders = async () => {
    try {
      const result = await openDesktopDialog({
        multiple: true,
        directory: true,
        title: "Select folders",
      })
      setTargets((current) => uniqueTargets(current, normalizeDialogResult(result)))
    } catch (err) {
      setError(messageFromError(err))
    }
  }

  const startScan = async (pathsOverride?: string[]) => {
    const scanTargets = pathsOverride ?? targets
    if (scanTargets.length === 0 || isScanning) return
    if (!desktopIpcAvailable) {
      setError(desktopIpcUnavailableMessage())
      return
    }

    setTargets(scanTargets)
    setError(null)
    setResults([])
    setFindings([])
    setEvents([])
    setSummary(emptySummary)
    setCurrentPath("")
    setSelectedPath(null)
    setIsScanning(true)

    const onEvent = new Channel<ScanEvent>()
    onEvent.onmessage = (message) => {
      if (message.event === "scanStarted") {
        setScanId(message.data.scanId)
        setEvents((current) => [
          `Scan ${message.data.scanId.slice(0, 8)} started`,
          ...current,
        ])
      }

      if (message.event === "fileStarted") {
        setCurrentPath(message.data.path)
      }

      if (message.event === "fileFinished") {
        setResults((current) => [message.data.result, ...current])
        setSelectedPath((current) => current ?? message.data.result.path)
      }

      if (message.event === "finding") {
        setFindings((current) => [message.data.finding, ...current])
      }

      if (message.event === "progress") {
        setSummary((current) => ({
          ...current,
          filesSeen: message.data.filesSeen,
          filesScanned: message.data.filesScanned,
          findings: message.data.findings,
        }))
        setCurrentPath(message.data.currentPath)
      }

      if (message.event === "scanCompleted") {
        setSummary(message.data.summary)
        setIsScanning(false)
        setScanId(null)
        setEvents((current) => [
          message.data.summary.canceled ? "Scan canceled" : "Scan completed",
          ...current,
        ])
      }

      if (message.event === "scanError") {
        setSummary((current) => ({ ...current, errors: current.errors + 1 }))
        setEvents((current) => [message.data.message, ...current])
      }
    }

    try {
      const response = await invokeCommand<StartScanResponse>("start_scan", {
        paths: scanTargets,
        options,
        onEvent,
      })
      setScanId(response.scanId)
    } catch (err) {
      setError(messageFromError(err))
      setIsScanning(false)
      setScanId(null)
    }
  }

  const cancelScan = async () => {
    if (!scanId) return
    try {
      await invokeCommand("cancel_scan", { scanId })
      setEvents((current) => ["Cancel requested", ...current])
    } catch (err) {
      setError(messageFromError(err))
    }
  }

  const runCompromiseSuite = async () => {
    const paths = selectedSuiteTargets.map((target) => target.path)
    setActiveSection("scan")
    await startScan(paths)
  }

  const toggleSuiteTarget = (target: CompromiseTarget, checked: boolean) => {
    setSelectedSuiteTargetIds((current) => {
      const next = new Set(current)
      if (checked) {
        next.add(target.id)
      } else {
        next.delete(target.id)
      }
      return next
    })
  }

  return (
    <TooltipProvider>
      <SidebarProvider
        style={
          {
            "--sidebar-width": "calc(var(--spacing) * 64)",
            "--header-height": "calc(var(--spacing) * 12)",
          } as CSSProperties
        }
      >
        <AppSidebar
          activeSection={activeSection}
          onSectionChange={setActiveSection}
          variant="inset"
        />
        <SidebarInset>
          <SiteHeader title={sectionTitles[activeSection]} />
          <div className="flex flex-1 flex-col gap-4 p-4 lg:p-6">
            {activeSection === "scan" ? (
              <ScanWorkspace
                cloudStatus={cloudStatus}
                engineStatus={engineStatus}
                targets={targets}
                targetInput={targetInput}
                setTargetInput={setTargetInput}
                addManualTarget={addManualTarget}
                pickFiles={pickFiles}
                pickFolders={pickFolders}
                setTargets={setTargets}
                isScanning={isScanning}
                startScan={() => startScan()}
                cancelScan={cancelScan}
                error={error}
                scanId={scanId}
                currentPath={currentPath}
                summary={summary}
                results={results}
                findings={findings}
                selectedResult={selectedResult}
                selectedPath={selectedPath}
                setSelectedPath={setSelectedPath}
                events={events}
                options={options}
                suspiciousResultCount={suspiciousResultCount}
                desktopIpcAvailable={desktopIpcAvailable}
              />
            ) : null}
            {activeSection === "compromise" ? (
              <CompromiseWorkspace
                suite={suite}
                selectedTargetIds={selectedSuiteTargetIds}
                selectedTargets={selectedSuiteTargets}
                onToggleTarget={toggleSuiteTarget}
                onRunSuite={runCompromiseSuite}
                isScanning={isScanning}
                summary={summary}
                findings={findings}
                suspiciousResultCount={suspiciousResultCount}
              />
            ) : null}
            {activeSection === "settings" ? (
              <SettingsWorkspace
                options={options}
                setOptions={setOptions}
                cloudStatus={cloudStatus}
                engineStatus={engineStatus}
              />
            ) : null}
          </div>
        </SidebarInset>
      </SidebarProvider>
    </TooltipProvider>
  )
}

function ScanWorkspace({
  cloudStatus,
  engineStatus,
  targets,
  targetInput,
  setTargetInput,
  addManualTarget,
  pickFiles,
  pickFolders,
  setTargets,
  isScanning,
  startScan,
  cancelScan,
  error,
  scanId,
  currentPath,
  summary,
  results,
  findings,
  selectedResult,
  selectedPath,
  setSelectedPath,
  events,
  options,
  suspiciousResultCount,
  desktopIpcAvailable,
}: {
  cloudStatus: CloudStatus | null
  engineStatus: EngineStatus | null
  targets: string[]
  targetInput: string
  setTargetInput: (value: string) => void
  addManualTarget: () => void
  pickFiles: () => void
  pickFolders: () => void
  setTargets: React.Dispatch<React.SetStateAction<string[]>>
  isScanning: boolean
  startScan: () => void
  cancelScan: () => void
  error: string | null
  scanId: string | null
  currentPath: string
  summary: ScanSummary
  results: ScanFileResult[]
  findings: Finding[]
  selectedResult: ScanFileResult | undefined
  selectedPath: string | null
  setSelectedPath: (path: string) => void
  events: string[]
  options: ScanOptions
  suspiciousResultCount: number
  desktopIpcAvailable: boolean
}) {
  return (
    <>
      <div className="grid gap-4 xl:grid-cols-[minmax(320px,0.82fr)_minmax(0,1.18fr)]">
        <Card>
          <CardHeader>
            <CardTitle>Targets</CardTitle>
            <CardDescription>{targets.length} selected</CardDescription>
            <CardAction>
              <div className="flex flex-wrap gap-2">
                <Badge variant={cloudStatus?.enabled ? "default" : "secondary"}>
                  <CloudIcon />
                  {cloudStatus?.enabled ? "Cloud ready" : "Cloud off"}
                </Badge>
                <Badge
                  variant={engineStatus?.loadErrors.length ? "outline" : "secondary"}
                >
                  <ShieldCheckIcon />
                  {engineStatus
                    ? `${engineStatus.externalYaraSources + engineStatus.builtInYaraSources} rules`
                    : "Rules"}
                </Badge>
              </div>
            </CardAction>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            {!desktopIpcAvailable ? (
              <div className="rounded-lg border border-dashed bg-muted/20 px-3 py-2 text-sm text-muted-foreground">
                {desktopIpcUnavailableMessage()}
              </div>
            ) : null}

            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                disabled={!desktopIpcAvailable || isScanning}
                onClick={pickFiles}
              >
                <FilePlusIcon />
                Files
              </Button>
              <Button
                variant="outline"
                disabled={!desktopIpcAvailable || isScanning}
                onClick={pickFolders}
              >
                <FolderOpenIcon />
                Folders
              </Button>
              <Button
                variant="ghost"
                disabled={targets.length === 0 || isScanning}
                onClick={() => setTargets([])}
              >
                <Trash2Icon />
                Clear
              </Button>
            </div>

            <div className="flex gap-2">
              <Input
                value={targetInput}
                onChange={(event) => setTargetInput(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") addManualTarget()
                }}
                placeholder="C:\Users\kevin\Downloads"
              />
              <Button
                variant="secondary"
                disabled={!desktopIpcAvailable || !targetInput.trim() || isScanning}
                onClick={addManualTarget}
              >
                <SearchIcon />
                Add
              </Button>
            </div>

            <div className="grid gap-2 rounded-lg border bg-muted/20 p-3 text-sm">
              <StatusLine
                label="Mode"
                value="Report-only. No quarantine, deletion, upload, or blocking."
              />
              <StatusLine
                label="Archives"
                value={
                  options.includeArchives
                    ? `On, depth ${options.maxArchiveDepth}`
                    : "Off"
                }
              />
              <StatusLine
                label="Cloud"
                value={
                  options.cloudLookup
                    ? "VirusTotal hash lookup on"
                    : "Hash lookup off"
                }
              />
              <StatusLine label="Max file" value={`${options.maxFileMb} MB`} />
            </div>

            <TargetList
              targets={targets}
              isScanning={isScanning}
              onRemove={(target) =>
                setTargets((current) => current.filter((item) => item !== target))
              }
            />

            <div className="flex flex-wrap items-center gap-2">
              <Button
                disabled={
                  !desktopIpcAvailable || targets.length === 0 || isScanning
                }
                onClick={startScan}
              >
                <PlayIcon />
                Scan
              </Button>
              <Button variant="destructive" disabled={!isScanning} onClick={cancelScan}>
                <SquareIcon />
                Cancel
              </Button>
              {error ? <span className="text-sm text-destructive">{error}</span> : null}
            </div>
          </CardContent>
        </Card>

        <div className="grid gap-4">
          <div className="grid grid-cols-[repeat(auto-fit,minmax(128px,1fr))] gap-4">
            <MetricCard icon={<SearchIcon />} label="Seen" value={summary.filesSeen} />
            <MetricCard
              icon={<ShieldCheckIcon />}
              label="Scanned"
              value={summary.filesScanned}
            />
            <MetricCard
              icon={<AlertTriangleIcon />}
              label="Findings"
              value={summary.findings}
            />
            <MetricCard
              icon={<ShieldAlertIcon />}
              label="Suspicious"
              value={suspiciousResultCount}
            />
            <MetricCard icon={<ArchiveIcon />} label="Skipped" value={summary.skipped} />
          </div>

          <ProgressCard
            isScanning={isScanning}
            scanId={scanId}
            currentPath={currentPath}
            summary={summary}
            cloudStatus={cloudStatus}
            engineStatus={engineStatus}
            desktopIpcAvailable={desktopIpcAvailable}
          />
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(340px,0.55fr)]">
        <ResultsTable
          results={results}
          selectedPath={selectedPath}
          selectedResult={selectedResult}
          setSelectedPath={setSelectedPath}
        />
        <DetailsCard selectedResult={selectedResult} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <FindingsCard findings={findings} />
        <EventsCard events={events} />
      </div>
    </>
  )
}

function CompromiseWorkspace({
  suite,
  selectedTargetIds,
  selectedTargets,
  onToggleTarget,
  onRunSuite,
  isScanning,
  summary,
  findings,
  suspiciousResultCount,
}: {
  suite: CompromiseCheckSuite | null
  selectedTargetIds: Set<string>
  selectedTargets: CompromiseTarget[]
  onToggleTarget: (target: CompromiseTarget, checked: boolean) => void
  onRunSuite: () => void
  isScanning: boolean
  summary: ScanSummary
  findings: Finding[]
  suspiciousResultCount: number
}) {
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(580px,1fr)_360px]">
      <div className="grid gap-4">
        <div className="grid grid-cols-[repeat(auto-fit,minmax(128px,1fr))] gap-4">
          <MetricCard
            icon={<FolderSearchIcon />}
            label="Targets"
            value={selectedTargets.length}
          />
          <MetricCard
            icon={<ShieldCheckIcon />}
            label="Scanned"
            value={summary.filesScanned}
          />
          <MetricCard
            icon={<AlertTriangleIcon />}
            label="Findings"
            value={findings.length}
          />
          <MetricCard
            icon={<ShieldAlertIcon />}
            label="Suspicious"
            value={suspiciousResultCount}
          />
        </div>

        {suite ? (
          suite.groups.map((group) => {
            const targets = suite.targets.filter(
              (target) => target.groupId === group.id
            )
            return (
              <Card key={group.id}>
                <CardHeader>
                  <CardTitle>{group.name}</CardTitle>
                  <CardDescription>{group.description}</CardDescription>
                  <CardAction>
                    <div className="flex flex-wrap gap-2">
                      <Badge variant={group.risk === "high" ? "outline" : "secondary"}>
                        {labelize(group.risk)} risk
                      </Badge>
                      <Badge variant="secondary">
                        {group.availableCount}/{group.targetCount} available
                      </Badge>
                    </div>
                  </CardAction>
                </CardHeader>
                <CardContent className="grid gap-2">
                  {targets.map((target) => (
                    <label
                      key={target.id}
                      className="grid gap-2 rounded-lg border p-3 text-sm sm:grid-cols-[auto_1fr_auto]"
                    >
                      <Checkbox
                        checked={selectedTargetIds.has(target.id)}
                        disabled={!target.recommended || isScanning}
                        onCheckedChange={(checked) =>
                          onToggleTarget(target, checked === true)
                        }
                      />
                      <div className="min-w-0">
                        <div className="font-medium">{target.label}</div>
                        <div className="truncate text-muted-foreground">
                          {target.path}
                        </div>
                      </div>
                      <Badge
                        variant={target.recommended ? "secondary" : "outline"}
                      >
                        {target.recommended ? "Ready" : target.reason ?? "Skipped"}
                      </Badge>
                    </label>
                  ))}
                </CardContent>
              </Card>
            )
          })
        ) : (
          <Card>
            <CardContent className="p-4 text-sm text-muted-foreground">
              Loading compromise-check targets
            </CardContent>
          </Card>
        )}
      </div>

      <div className="grid content-start gap-4">
        <Card>
          <CardHeader>
            <CardTitle>Run Suite</CardTitle>
            <CardDescription>
              Efficient preset scan using existing report-only engines.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4">
            <div className="rounded-lg border bg-muted/20 p-3 text-sm text-muted-foreground">
              This checks files and metadata only. It does not remove files,
              install drivers, upload samples, or block processes.
            </div>
            <Button
              disabled={!suite || selectedTargets.length === 0 || isScanning}
              onClick={onRunSuite}
            >
              <PlayIcon />
              Run selected suite
            </Button>
            <div className="grid gap-2 text-sm">
              <StatusLine
                label="Selected paths"
                value={String(selectedTargets.length)}
              />
              <StatusLine
                label="Archive depth"
                value="Uses current scanner settings"
              />
              <StatusLine label="Cloud" value="Uses current scanner settings" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Next Actions</CardTitle>
            <CardDescription>Use after reviewing results.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-2">
            {(suite?.nextActions ?? []).map((action) => (
              <div
                key={action}
                className="flex gap-2 rounded-lg border p-3 text-sm"
              >
                <CheckCircle2Icon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                <span>{action}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

function SettingsWorkspace({
  options,
  setOptions,
  cloudStatus,
  engineStatus,
}: {
  options: ScanOptions
  setOptions: React.Dispatch<React.SetStateAction<ScanOptions>>
  cloudStatus: CloudStatus | null
  engineStatus: EngineStatus | null
}) {
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(520px,0.85fr)_minmax(460px,1fr)]">
      <Card>
        <CardHeader>
          <CardTitle>Scanner Options</CardTitle>
          <CardDescription>
            Defaults favor useful coverage without modifying the system.
          </CardDescription>
          <CardAction>
            <Button variant="outline" onClick={() => setOptions(defaultOptions)}>
              <RotateCcwIcon />
              Reset
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent className="grid gap-4">
          <label className="flex items-start gap-3 rounded-lg border p-3 text-sm">
            <Checkbox
              checked={options.includeArchives}
              onCheckedChange={(checked) =>
                setOptions((current) => ({
                  ...current,
                  includeArchives: checked === true,
                }))
              }
            />
            <ArchiveIcon className="mt-0.5 size-4 text-muted-foreground" />
            <div className="grid gap-1">
              <span className="font-medium">Scan archives</span>
              <span className="text-muted-foreground">
                Recurse through zip, tar, and gzip content up to the configured depth.
              </span>
            </div>
          </label>

          <label className="flex items-start gap-3 rounded-lg border p-3 text-sm">
            <Checkbox
              checked={options.cloudLookup}
              disabled={!cloudStatus?.enabled}
              onCheckedChange={(checked) =>
                setOptions((current) => ({
                  ...current,
                  cloudLookup: checked === true,
                }))
              }
            />
            <CloudIcon className="mt-0.5 size-4 text-muted-foreground" />
            <div className="grid gap-1">
              <span className="font-medium">VirusTotal hash lookup</span>
              <span className="text-muted-foreground">
                Hash-only lookup. Disabled unless `VIRUSTOTAL_API_KEY` is set.
              </span>
              {!cloudStatus?.enabled && cloudStatus?.reason ? (
                <span className="text-destructive">{cloudStatus.reason}</span>
              ) : null}
            </div>
          </label>

          <div className="grid gap-3 sm:grid-cols-2">
            <div className="grid gap-1.5">
              <Label htmlFor="settings-max-file-mb">Max file MB</Label>
              <Input
                id="settings-max-file-mb"
                type="number"
                min={1}
                max={4096}
                value={options.maxFileMb}
                onChange={(event) =>
                  setOptions((current) => ({
                    ...current,
                    maxFileMb: clampNumber(Number(event.target.value), 1, 4096),
                  }))
                }
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="settings-archive-depth">Max archive depth</Label>
              <Input
                id="settings-archive-depth"
                type="number"
                min={0}
                max={8}
                value={options.maxArchiveDepth}
                onChange={(event) =>
                  setOptions((current) => ({
                    ...current,
                    maxArchiveDepth: clampNumber(Number(event.target.value), 0, 8),
                  }))
                }
              />
            </div>
          </div>

          <div className="rounded-lg border bg-muted/20 p-3 text-sm text-muted-foreground">
            Report-only means findings are evidence for review. The app does not
            quarantine, delete, upload samples, install a real-time provider, or
            block execution.
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-4">
        <Card>
          <CardHeader>
            <CardTitle>Engine Status</CardTitle>
            <CardDescription>Local scanners and signature sources.</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3">
            <StatusPanel
              icon={<ShieldCheckIcon />}
              label="YARA rules"
              value={
                engineStatus
                  ? `${engineStatus.builtInYaraSources} built-in, ${engineStatus.externalYaraSources} external`
                  : "Loading"
              }
              state={engineStatus?.loadErrors.length ? "check" : "ready"}
            />
            <StatusPanel
              icon={<HardDriveIcon />}
              label="Hash database"
              value={
                engineStatus
                  ? `${engineStatus.hashIndicators} local indicators`
                  : "Loading"
              }
              state={engineStatus?.hashIndicators ? "ready" : "check"}
            />
            <StatusPanel
              icon={<FileIcon />}
              label="Magika"
              value={
                engineStatus?.magikaAvailable
                  ? "Content classification ready"
                  : engineStatus?.magikaError ?? "Unavailable"
              }
              state={engineStatus?.magikaAvailable ? "ready" : "check"}
            />
            <StatusPanel
              icon={<CloudIcon />}
              label="Cloud"
              value={
                cloudStatus?.enabled
                  ? "VirusTotal hash lookup ready"
                  : cloudStatus?.reason ?? "Unavailable"
              }
              state={cloudStatus?.enabled ? "ready" : "check"}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Sources</CardTitle>
            <CardDescription>Configured local rule and hash inputs.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="max-h-56 divide-y overflow-auto rounded-lg border">
              {(engineStatus?.signatureSources.length ?? 0) === 0 ? (
                <div className="p-4 text-sm text-muted-foreground">
                  No external sources configured
                </div>
              ) : (
                engineStatus?.signatureSources.map((source) => (
                  <div key={source} className="truncate px-3 py-2 text-sm">
                    {source}
                  </div>
                ))
              )}
            </div>
            {engineStatus?.loadErrors.length ? (
              <div className="mt-3 grid gap-2">
                {engineStatus.loadErrors.map((loadError) => (
                  <div
                    key={loadError}
                    className="rounded-lg border border-dashed p-3 text-sm text-muted-foreground"
                  >
                    {loadError}
                  </div>
                ))}
              </div>
            ) : null}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

function TargetList({
  targets,
  isScanning,
  onRemove,
}: {
  targets: string[]
  isScanning: boolean
  onRemove: (target: string) => void
}) {
  return (
    <div className="min-h-24 rounded-lg border bg-muted/25">
      {targets.length === 0 ? (
        <div className="flex h-24 items-center px-3 text-sm text-muted-foreground">
          No targets selected
        </div>
      ) : (
        <div className="max-h-44 divide-y overflow-auto">
          {targets.map((target) => (
            <div
              key={target}
              className="flex items-center justify-between gap-2 px-3 py-2 text-sm"
            >
              <span className="min-w-0 truncate">{target}</span>
              <Button
                variant="ghost"
                size="icon-sm"
                disabled={isScanning}
                onClick={() => onRemove(target)}
              >
                <Trash2Icon />
              </Button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function ProgressCard({
  isScanning,
  scanId,
  currentPath,
  summary,
  cloudStatus,
  engineStatus,
  desktopIpcAvailable,
}: {
  isScanning: boolean
  scanId: string | null
  currentPath: string
  summary: ScanSummary
  cloudStatus: CloudStatus | null
  engineStatus: EngineStatus | null
  desktopIpcAvailable: boolean
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Progress</CardTitle>
        <CardDescription>
          {isScanning ? "Running" : summary.canceled ? "Canceled" : "Idle"}
        </CardDescription>
        <CardAction>
          <Badge variant={isScanning ? "outline" : "secondary"}>
            {scanId ? scanId.slice(0, 8) : "No scan"}
          </Badge>
        </CardAction>
      </CardHeader>
      <CardContent className="grid gap-3">
        <div className="min-h-10 rounded-lg border bg-muted/25 px-3 py-2 text-sm">
          <div className="truncate text-foreground">
            {currentPath || "No active file"}
          </div>
        </div>
        <div className="grid gap-2 sm:grid-cols-[1fr_220px]">
          <div className="h-2 overflow-hidden rounded-full bg-muted">
            <div
              className="h-full bg-primary transition-all"
              style={{
                width: `${Math.min(
                  100,
                  summary.filesSeen
                    ? (summary.filesScanned / summary.filesSeen) * 100
                    : 0
                )}%`,
              }}
            />
          </div>
          <div className="text-sm text-muted-foreground">
            {summary.errors} errors
          </div>
        </div>
        {!desktopIpcAvailable ? (
          <div className="rounded-lg border border-dashed px-3 py-2 text-sm text-muted-foreground">
            {desktopIpcUnavailableMessage()}
          </div>
        ) : null}
        {desktopIpcAvailable && cloudStatus?.reason ? (
          <div className="rounded-lg border border-dashed px-3 py-2 text-sm text-muted-foreground">
            {cloudStatus.reason}
          </div>
        ) : null}
        {desktopIpcAvailable && engineStatus ? (
          <div className="rounded-lg border border-dashed px-3 py-2 text-sm text-muted-foreground">
            {engineStatus.externalYaraSources} external YARA sources,{" "}
            {engineStatus.hashIndicators} hash indicators, Magika{" "}
            {engineStatus.magikaAvailable ? "ready" : "off"}
            {engineStatus.loadErrors.length
              ? `, ${engineStatus.loadErrors.length} load errors`
              : ""}
            {engineStatus.magikaError ? `, ${engineStatus.magikaError}` : ""}
          </div>
        ) : null}
      </CardContent>
    </Card>
  )
}

function ResultsTable({
  results,
  selectedPath,
  selectedResult,
  setSelectedPath,
}: {
  results: ScanFileResult[]
  selectedPath: string | null
  selectedResult: ScanFileResult | undefined
  setSelectedPath: (path: string) => void
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Results</CardTitle>
        <CardDescription>{results.length} rows</CardDescription>
      </CardHeader>
      <CardContent>
        <Table className="min-w-[760px]">
          <TableHeader>
            <TableRow>
              <TableHead>Verdict</TableHead>
              <TableHead>Path</TableHead>
              <TableHead>Size</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Cloud</TableHead>
              <TableHead>Static</TableHead>
              <TableHead>Hash</TableHead>
              <TableHead>YARA</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {results.length === 0 ? (
              <TableRow>
                <TableCell colSpan={8} className="h-28 text-center text-muted-foreground">
                  No results
                </TableCell>
              </TableRow>
            ) : (
              results.map((result) => (
                <TableRow
                  key={`${result.path}-${result.sha256}-${result.archiveDepth}`}
                  data-state={
                    (selectedPath ?? selectedResult?.path) === result.path
                      ? "selected"
                      : undefined
                  }
                  className="cursor-pointer"
                  onClick={() => setSelectedPath(result.path)}
                >
                  <TableCell>
                    <Badge variant={verdictVariant(result.verdict)}>
                      {labelize(result.verdict)}
                    </Badge>
                  </TableCell>
                  <TableCell className="max-w-[420px] truncate">
                    {result.path}
                  </TableCell>
                  <TableCell>{formatBytes(result.size)}</TableCell>
                  <TableCell className="max-w-[96px] truncate">
                    {result.content?.label ?? "-"}
                  </TableCell>
                  <TableCell>
                    <Badge variant={verdictVariant(result.cloud.verdict)}>
                      {labelize(result.cloud.verdict)}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={
                        result.staticAnalysis.threatScore >= 35
                          ? "outline"
                          : "secondary"
                      }
                    >
                      {formatScore(result.staticAnalysis.threatScore)}
                    </Badge>
                  </TableCell>
                  <TableCell>{result.hashMatches.length || "-"}</TableCell>
                  <TableCell className="max-w-[180px] truncate">
                    {result.yaraMatches.join(", ") || "-"}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

function DetailsCard({
  selectedResult,
}: {
  selectedResult: ScanFileResult | undefined
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Details</CardTitle>
        <CardDescription>
          {selectedResult ? labelize(selectedResult.verdict) : "None"}
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        {selectedResult ? (
          <>
            <DetailRow label="Path" value={selectedResult.path} />
            <DetailRow label="SHA-256" value={selectedResult.sha256 || "-"} mono />
            <DetailRow label="BLAKE3" value={selectedResult.blake3 || "-"} mono />
            <DetailRow
              label="Cloud"
              value={selectedResult.cloud.reason ?? labelize(selectedResult.cloud.verdict)}
            />
            {selectedResult.content ? (
              <div className="grid gap-2 rounded-lg border p-3">
                <div className="text-sm font-medium">File type</div>
                <DetailRow
                  label="Label"
                  value={`${selectedResult.content.description} (${selectedResult.content.label})`}
                />
                <DetailRow label="MIME" value={selectedResult.content.mimeType} />
                <DetailRow label="Group" value={selectedResult.content.group} />
                <DetailRow
                  label="Confidence"
                  value={`${Math.round(selectedResult.content.score * 100)}%`}
                />
              </div>
            ) : null}
            {selectedResult.hashMatches.length ? (
              <div className="grid gap-2 rounded-lg border p-3">
                <div className="text-sm font-medium">Hash indicators</div>
                {selectedResult.hashMatches.map((indicator) => (
                  <DetailRow
                    key={`${indicator.algorithm}-${indicator.hash}`}
                    label={indicator.algorithm.toUpperCase()}
                    value={`${indicator.name} (${labelize(indicator.verdict)})`}
                  />
                ))}
              </div>
            ) : null}
            {selectedResult.windowsAttributes ? (
              <div className="grid gap-2 rounded-lg border p-3">
                <div className="text-sm font-medium">Windows attributes</div>
                <DetailRow
                  label="Flags"
                  value={
                    Object.entries(selectedResult.windowsAttributes)
                      .filter(([, enabled]) => enabled)
                      .map(([name]) => labelize(name))
                      .join(", ") || "-"
                  }
                />
              </div>
            ) : null}
            {selectedResult.skippedReason ? (
              <DetailRow label="Skipped" value={selectedResult.skippedReason} />
            ) : null}
            {selectedResult.error ? (
              <DetailRow label="Error" value={selectedResult.error} />
            ) : null}
            <div className="grid gap-2 rounded-lg border p-3">
              <div className="text-sm font-medium">Static analysis</div>
              <DetailRow
                label="Threat score"
                value={formatScore(selectedResult.staticAnalysis.threatScore)}
              />
              <DetailRow
                label="Entropy"
                value={selectedResult.staticAnalysis.entropy.toFixed(2)}
              />
              <DetailRow
                label="Packer"
                value={
                  selectedResult.staticAnalysis.packer.detected
                    ? `${selectedResult.staticAnalysis.packer.name} (${Math.round(
                        selectedResult.staticAnalysis.packer.confidence * 100
                      )}%)`
                    : "None"
                }
              />
              <DetailRow
                label="Signals"
                value={selectedResult.staticAnalysis.signals.join(", ") || "-"}
              />
            </div>
            {selectedResult.executable ? (
              <div className="grid gap-2 rounded-lg border p-3">
                <div className="text-sm font-medium">Executable metadata</div>
                <DetailRow label="Format" value={selectedResult.executable.format} />
                <DetailRow
                  label="Architecture"
                  value={selectedResult.executable.architecture}
                />
                <DetailRow
                  label="Sections"
                  value={String(selectedResult.executable.sections)}
                />
                <DetailRow
                  label="Imports"
                  value={selectedResult.executable.imports.join(", ") || "-"}
                />
              </div>
            ) : null}
          </>
        ) : (
          <div className="min-h-48 rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
            Select a result
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function FindingsCard({ findings }: { findings: Finding[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Findings</CardTitle>
        <CardDescription>{findings.length} active</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-2">
        {findings.length === 0 ? (
          <div className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">
            No findings
          </div>
        ) : (
          findings.map((finding) => (
            <div
              key={`${finding.path}-${finding.title}`}
              className="grid gap-1 rounded-lg border p-3 text-sm"
            >
              <div className="flex items-center justify-between gap-2">
                <div className="min-w-0 truncate font-medium">{finding.title}</div>
                <Badge variant={verdictVariant(finding.verdict)}>
                  {finding.source}
                </Badge>
              </div>
              <div className="truncate text-muted-foreground">{finding.path}</div>
            </div>
          ))
        )}
      </CardContent>
    </Card>
  )
}

function EventsCard({ events }: { events: string[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Event Stream</CardTitle>
        <CardDescription>{events.length} events</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="max-h-48 divide-y overflow-auto rounded-lg border">
          {events.length === 0 ? (
            <div className="p-4 text-sm text-muted-foreground">No events</div>
          ) : (
            events.map((event, index) => (
              <div key={`${event}-${index}`} className="px-3 py-2 text-sm">
                {event}
              </div>
            ))
          )}
        </div>
      </CardContent>
    </Card>
  )
}

function MetricCard({
  icon,
  label,
  value,
}: {
  icon: ReactNode
  label: string
  value: number
}) {
  return (
    <Card size="sm">
      <CardContent className="flex min-h-20 items-center justify-between gap-3">
        <div className="grid min-w-0 gap-1">
          <div className="truncate text-sm text-muted-foreground">{label}</div>
          <div className="text-2xl leading-none font-semibold">{value}</div>
        </div>
        <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground">
          {icon}
        </div>
      </CardContent>
    </Card>
  )
}

function StatusPanel({
  icon,
  label,
  value,
  state,
}: {
  icon: ReactNode
  label: string
  value: string
  state: "ready" | "check"
}) {
  return (
    <div className="flex items-start gap-3 rounded-lg border p-3 text-sm">
      <div className="mt-0.5 text-muted-foreground">{icon}</div>
      <div className="min-w-0 flex-1">
        <div className="font-medium">{label}</div>
        <div className="break-words text-muted-foreground">{value}</div>
      </div>
      <Badge variant={state === "ready" ? "secondary" : "outline"}>
        {state === "ready" ? "Ready" : "Check"}
      </Badge>
    </div>
  )
}

function StatusLine({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-1 sm:grid-cols-[132px_1fr]">
      <div className="text-muted-foreground">{label}</div>
      <div className="break-words">{value}</div>
    </div>
  )
}

function DetailRow({
  label,
  value,
  mono,
}: {
  label: string
  value: string
  mono?: boolean
}) {
  return (
    <div className="grid gap-1 text-sm">
      <div className="text-muted-foreground">{label}</div>
      <div className={mono ? "break-all font-mono text-xs" : "break-words"}>
        {value}
      </div>
    </div>
  )
}
