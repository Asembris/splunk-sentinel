const fontFamily = "-apple-system, 'Segoe UI', sans-serif"

function LogoMark() {
  return (
    <g transform="translate(28, 28)">
      <polygon
        fill="#08111f"
        stroke="#60a5fa"
        points="0,-23 20,-12 20,10 0,24 -20,10 -20,-12"
        strokeWidth="1.6"
      />
      <polygon
        fill="#0f1b2e"
        stroke="#2563eb"
        points="0,-17 14.7,-8.5 14.7,8.5 0,17 -14.7,8.5 -14.7,-8.5"
        strokeWidth="1"
        opacity="0.95"
      />
      <path
        d="M-11 -6.5 L0 -12 L11 -6.5 M-11 6.5 L0 12 L11 6.5"
        stroke="#1d4ed8"
        fill="none"
        strokeWidth="0.9"
        opacity="0.9"
      />
      <path
        d="M-11 -6.5 L-11 6.5 M11 -6.5 L11 6.5"
        stroke="#1d4ed8"
        fill="none"
        strokeWidth="0.9"
        opacity="0.65"
      />
      <circle cx="0" cy="0" r="10" stroke="#60a5fa" fill="none" strokeWidth="0.8" opacity="0.48" />
      <circle cx="0" cy="0" r="5.7" stroke="#3b82f6" fill="#0b1220" strokeWidth="1" opacity="0.95" />
      <path
        d="M-13.5 0 H-6.4 M6.4 0 H13.5 M0 -13.5 V-6.4 M0 6.4 V13.5"
        stroke="#60a5fa"
        fill="none"
        strokeWidth="0.9"
        opacity="0.9"
      />
      <path
        d="M-3.1 0.4 L-0.8 2.8 L4.2 -3.2"
        stroke="#93c5fd"
        fill="none"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
      />
      <circle cx="-11" cy="-6.5" r="1.3" fill="#3b82f6" />
      <circle cx="11" cy="-6.5" r="1.3" fill="#3b82f6" />
      <circle cx="-11" cy="6.5" r="1.3" fill="#3b82f6" />
      <circle cx="11" cy="6.5" r="1.3" fill="#3b82f6" />
      <circle cx="0" cy="0" r="2.1" fill="#60a5fa" />
    </g>
  )
}

export default function BrandLogo({ variant = 'full', className = '' }) {
  if (variant === 'mark') {
    return (
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 56 56"
        role="img"
        aria-labelledby="splunk-sentinel-mark-title splunk-sentinel-mark-desc"
        className={className || 'h-12 w-12'}
      >
        <title id="splunk-sentinel-mark-title">Splunk Sentinel</title>
        <desc id="splunk-sentinel-mark-desc">Splunk Sentinel agentic SOC platform mark</desc>
        <LogoMark />
      </svg>
    )
  }

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 164 56"
      role="img"
      aria-labelledby="splunk-sentinel-logo-title splunk-sentinel-logo-desc"
      className={className || 'h-10 w-auto'}
    >
      <title id="splunk-sentinel-logo-title">Splunk Sentinel</title>
      <desc id="splunk-sentinel-logo-desc">Splunk Sentinel agentic SOC platform logo</desc>
      <LogoMark />

      <line x1="54" y1="12" x2="54" y2="44" stroke="#1e3a5f" fill="none" strokeWidth="0.6" />

      <text
        x="62"
        y="27"
        fill="#ffffff"
        fontFamily={fontFamily}
        fontSize="15"
        fontWeight="700"
        letterSpacing="0"
      >
        Splunk
      </text>
      <text
        x="62"
        y="42"
        fill="#3b82f6"
        fontFamily={fontFamily}
        fontSize="14"
        fontWeight="700"
        letterSpacing="2.5"
      >
        SENTINEL
      </text>
    </svg>
  )
}
