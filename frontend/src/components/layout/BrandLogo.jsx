const fontFamily = "-apple-system, 'Segoe UI', sans-serif"

function LogoMark() {
  return (
    <g transform="translate(28, 28)">
      <polygon
        fill="#0d1117"
        stroke="#3b82f6"
        points="0,-22 19,-11 19,11 0,22 -19,11 -19,-22"
        strokeWidth="1"
      />
      <polygon
        fill="#161f2e"
        stroke="#3b82f6"
        points="0,-16 13.9,-8 13.9,8 0,16 -13.9,8 -13.9,-8"
        strokeWidth="0.6"
        opacity="0.85"
      />
      <circle cx="0" cy="0" r="10" stroke="#3b82f6" fill="none" strokeWidth="0.45" opacity="0.35" />
      <circle cx="0" cy="0" r="6" stroke="#3b82f6" fill="none" strokeWidth="0.55" opacity="0.55" />
      <line x1="-13.9" y1="0" x2="13.9" y2="0" stroke="#3b82f6" fill="none" strokeWidth="0.5" opacity="0.75" />
      <line x1="0" y1="-16" x2="0" y2="16" stroke="#3b82f6" fill="none" strokeWidth="0.5" opacity="0.75" />
      <circle cx="0" cy="0" r="2" fill="#3b82f6" />
      <line x1="-2" y1="0" x2="-6" y2="0" stroke="#3b82f6" fill="none" strokeWidth="0.8" />
      <line x1="2" y1="0" x2="6" y2="0" stroke="#3b82f6" fill="none" strokeWidth="0.8" />
      <line x1="0" y1="-2" x2="0" y2="-6" stroke="#3b82f6" fill="none" strokeWidth="0.8" />
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
