// Shapes of what the integration's websocket commands return. Loose on
// purpose: the backend is the source of truth and adds fields over time.

export interface Hass {
  callWS<T>(msg: Record<string, unknown>): Promise<T>;
  user?: { is_admin?: boolean; name?: string };
  themes?: { darkMode?: boolean };
  language?: string;
}

export interface PhoneHome {
  attempts: number;
  blocked: number;
  allowed: number;
  blocked_by_our_rule: number;
  window_minutes: number | null;
  top_destinations: { host: string; port: number | null; region: string; protocol: string; count: number }[];
  regions: Record<string, number>;
  clouds: Record<string, number>;
  dns_bypass: Record<string, number>;
  port_sweep: { host: string; ports: number } | null;
}

export interface Finding {
  cve: string;
  status: "affected" | "likely" | "check";
  kev: boolean;
  detail: string;
  source: string;
}

export interface Vulns {
  family: string | null;
  firmware: string;
  firmware_date: string | null;
  firmware_age_years: number | null;
  findings: Finding[];
  worst: "affected" | "likely" | "check" | null;
}

export interface HomeAutomation {
  brand: string;
  tier: "local" | "cloud_local" | "cloud" | "unknown";
  tier_label: string;
  local_option: string;
}

export interface Client {
  mac: string;
  name: string;
  hostname: string;
  ip: string;
  vendor: string;
  network?: string;
  blocked: boolean;
  wired: boolean;
  rssi?: number | null;
  signal?: number | null;
  channel?: number | null;
  radio?: string;
  essid?: string;
  experience?: number | null;
  uptime_seconds?: number | null;
  tx_bytes?: number | null;
  rx_bytes?: number | null;
  state: "new" | "trusted" | "ignored" | "quarantined";
  first_seen?: number | string | null;
  last_seen?: number | string | null;
  suspicious: boolean;
  threat_level: string;
  suspicion_score: number;
  suspicion_flags: string[];
  is_camera: boolean;
  category: string;
  category_label: string;
  category_icon: string;
  confidence: string;
  source: string;
  onvif_manufacturer?: string;
  onvif_model?: string;
  onvif_firmware?: string;
  onvif_serial?: string;
  onvif?: { onvif: boolean; manufacturer: string; model: string; firmware_version: string; serial_number: string; auth_required: boolean } | null;
  vulns?: Vulns | null;
  unifi_fingerprint?: { dev_cat: number | null; dev_family: number | null; os_name: string | null; camera: boolean } | null;
  security_events_24h?: number;
  blocked_by_rule_24h?: number;
  traffic_24h?: number[] | null;
  traffic_spike?: { last_hour_bytes: number; usual_bytes: number; factor: number | null } | null;
  phone_home?: PhoneHome | null;
  watched?: boolean;
  internet_blocked?: boolean;
  containment?: "holding" | "quiet" | "leaking" | null;
  home_automation?: HomeAutomation | null;
  ip_history?: { ip: string; until: string; type: string }[];
  manual_category?: string | null;
  suggested_category?: { category: string; confidence: string; description: string } | null;
  dpi?: { total_rx_mb?: number; total_tx_mb?: number; top_categories?: { category: string; rx_mb: number; tx_mb: number }[] };
}

export interface SecurityEvent {
  key: string;
  msg: string;
  title?: string;
  time: number | null;
  mac?: string;
  src_ip?: string;
  dst_ip?: string;
  catname?: string;
  inner_alert_severity?: string;
  rule?: string;
}

export interface Hotspot {
  essid: string;
  bssid: string;
  rssi: number | null;
  channel: number | null;
  security: string;
  reason: "own_camera" | "camera_ssid";
  camera_mac: string | null;
  camera_name: string;
}

export interface Overview {
  total_clients?: number;
  new_count?: number;
  suspicious_count?: number;
  blocked_count?: number;
  quarantined_count?: number;
  trusted_count?: number;
  ignored_count?: number;
  wireless_count?: number;
  wired_count?: number;
  threat_events?: number;
  security_events?: SecurityEvent[];
  contained_blocks_24h?: number;
  hotspots?: Hotspot[];
  health?: { connection_ok?: boolean; hostname?: string; version?: string; uptime?: number; [k: string]: unknown };
  category_counts?: Record<string, number>;
  category_labels?: Record<string, string>;
  category_icons?: Record<string, string>;
}

export interface Rec {
  priority: "critical" | "high" | "medium" | "low" | "info";
  priority_label: string;
  title: string;
  detail: string;
  action: string;
  action_data: Record<string, unknown>;
  mac?: string;
}

export interface Recommendations {
  device_recs?: Record<string, Rec[]>;
  network_recs?: Rec[];
  total_device_recs?: number;
  critical_count?: number;
  high_count?: number;
}

export interface LocalNet {
  assignments?: Record<string, { ip: string; category: string; name?: string; [k: string]: unknown }>;
  ranges?: { category: string; range: string; used: number; total: number; [k: string]: unknown }[];
  firewall?: { exists?: boolean; enabled?: boolean; blocked_count?: number; total_devices?: number; name?: string };
  range_block?: { supported: boolean; enabled: boolean; cidr: string | null; ntp_allowed?: boolean; reason?: string };
  subnet?: string;
  prefix?: string;
}

export interface Miners {
  rigs: Record<string, any>[];
  summary: Record<string, number>;
  pro?: boolean;
}

export interface Licence {
  pro: boolean;
  has_key: boolean;
  active?: boolean;
  expires?: string;
  days_left?: number | null;
  in_grace?: boolean;
  trial?: boolean;
  trial_used?: boolean;
  price?: string;
  buy_url?: string;
  trial_days?: number;
  grace_days?: number;
}

export interface ScanResult {
  status: string;
  ip?: string;
  open_ports?: number[];
  port_details?: { port: number; name: string; group: string }[];
  guess_category?: string;
  guess_description?: string;
  guess_confidence?: string;
  guess_risk?: string;
  warnings?: string[];
  recommendations?: string[];
  scan_time?: number;
}

export interface ReportStatus {
  enabled: boolean;
  has_id: boolean;
  last_day: string;
  url: string;
}

export interface LearnedRules {
  vendor_rules: Record<string, string>;
  hostname_rules: Record<string, string>;
  mac_rules: Record<string, string>;
  port_rules: { ports: number[]; category: string }[];
  total_rules: number;
}

export interface Snapshot {
  overview: Overview;
  clients: Client[];
  recs: Recommendations;
  localnet: LocalNet;
  miners: Miners;
  scans: Record<string, ScanResult>;
  report: ReportStatus | null;
  learned: LearnedRules | null;
  licence: Licence;
  loaded: boolean;
  error: string;
  updated: number;
}
