/**
 * Geographic transformation utilities for attack map visualization.
 * Converts location data to coordinates and aggregates attacks by location.
 */

// Country code to approximate center coordinates
const COUNTRY_COORDINATES = {
  US: { lat: 37.0902, lon: -95.7129, name: 'United States' },
  CN: { lat: 35.8617, lon: 104.1954, name: 'China' },
  RU: { lat: 61.524, lon: 105.3188, name: 'Russia' },
  DE: { lat: 51.1657, lon: 10.4515, name: 'Germany' },
  GB: { lat: 55.3781, lon: -3.436, name: 'United Kingdom' },
  FR: { lat: 46.2276, lon: 2.2137, name: 'France' },
  JP: { lat: 36.2048, lon: 138.2529, name: 'Japan' },
  BR: { lat: -14.235, lon: -51.9253, name: 'Brazil' },
  IN: { lat: 20.5937, lon: 78.9629, name: 'India' },
  AU: { lat: -25.2744, lon: 133.7751, name: 'Australia' },
  CA: { lat: 56.1304, lon: -106.3468, name: 'Canada' },
  KR: { lat: 35.9078, lon: 127.7669, name: 'South Korea' },
  NL: { lat: 52.1326, lon: 5.2913, name: 'Netherlands' },
  UA: { lat: 48.3794, lon: 31.1656, name: 'Ukraine' },
  PL: { lat: 51.9194, lon: 19.1451, name: 'Poland' },
  IR: { lat: 32.4279, lon: 53.688, name: 'Iran' },
  VN: { lat: 14.0583, lon: 108.2772, name: 'Vietnam' },
  ID: { lat: -0.7893, lon: 113.9213, name: 'Indonesia' },
  TR: { lat: 38.9637, lon: 35.2433, name: 'Turkey' },
  NG: { lat: 9.082, lon: 8.6753, name: 'Nigeria' },
  MX: { lat: 23.6345, lon: -102.5528, name: 'Mexico' },
  AR: { lat: -38.4161, lon: -63.6167, name: 'Argentina' },
  ZA: { lat: -30.5595, lon: 22.9375, name: 'South Africa' },
  TH: { lat: 15.87, lon: 100.9925, name: 'Thailand' },
  PH: { lat: 12.8797, lon: 121.774, name: 'Philippines' },
  IT: { lat: 41.8719, lon: 12.5674, name: 'Italy' },
  ES: { lat: 40.4637, lon: -3.7492, name: 'Spain' },
  SE: { lat: 60.1282, lon: 18.6435, name: 'Sweden' },
  CH: { lat: 46.8182, lon: 8.2275, name: 'Switzerland' },
  SG: { lat: 1.3521, lon: 103.8198, name: 'Singapore' },
  MY: { lat: 4.2105, lon: 101.9758, name: 'Malaysia' },
  EG: { lat: 26.8206, lon: 30.8025, name: 'Egypt' },
  PK: { lat: 30.3753, lon: 69.3451, name: 'Pakistan' },
  BD: { lat: 23.685, lon: 90.3563, name: 'Bangladesh' },
  RO: { lat: 45.9432, lon: 24.9668, name: 'Romania' },
  HK: { lat: 22.3193, lon: 114.1694, name: 'Hong Kong' },
  TW: { lat: 23.6978, lon: 120.9605, name: 'Taiwan' },
  IL: { lat: 31.0461, lon: 34.8516, name: 'Israel' },
  NO: { lat: 60.472, lon: 8.4689, name: 'Norway' },
  FI: { lat: 61.9241, lon: 25.7482, name: 'Finland' },
  DK: { lat: 56.2639, lon: 9.5018, name: 'Denmark' },
  BE: { lat: 50.5039, lon: 4.4699, name: 'Belgium' },
  AT: { lat: 47.5162, lon: 14.5501, name: 'Austria' },
  CZ: { lat: 49.8175, lon: 15.473, name: 'Czech Republic' },
  GR: { lat: 39.0742, lon: 21.8243, name: 'Greece' },
  PT: { lat: 39.3999, lon: -8.2245, name: 'Portugal' },
  IE: { lat: 53.4129, lon: -8.2439, name: 'Ireland' },
  NZ: { lat: -40.9006, lon: 174.886, name: 'New Zealand' },
  CL: { lat: -35.6751, lon: -71.543, name: 'Chile' },
  CO: { lat: 4.5709, lon: -74.2973, name: 'Colombia' },
  VE: { lat: 6.4238, lon: -66.5897, name: 'Venezuela' },
  PE: { lat: -9.19, lon: -75.0152, name: 'Peru' },
  KP: { lat: 40.3399, lon: 127.5101, name: 'North Korea' },
  BY: { lat: 53.7098, lon: 27.9534, name: 'Belarus' },
}

// Major city coordinates for more precise mapping
const CITY_COORDINATES = {
  'New York': { lat: 40.7128, lon: -74.006, country: 'US' },
  'Los Angeles': { lat: 34.0522, lon: -118.2437, country: 'US' },
  Chicago: { lat: 41.8781, lon: -87.6298, country: 'US' },
  Beijing: { lat: 39.9042, lon: 116.4074, country: 'CN' },
  Shanghai: { lat: 31.2304, lon: 121.4737, country: 'CN' },
  Moscow: { lat: 55.7558, lon: 37.6173, country: 'RU' },
  'Saint Petersburg': { lat: 59.9311, lon: 30.3609, country: 'RU' },
  London: { lat: 51.5074, lon: -0.1278, country: 'GB' },
  Paris: { lat: 48.8566, lon: 2.3522, country: 'FR' },
  Berlin: { lat: 52.52, lon: 13.405, country: 'DE' },
  Tokyo: { lat: 35.6762, lon: 139.6503, country: 'JP' },
  Sydney: { lat: -33.8688, lon: 151.2093, country: 'AU' },
  Toronto: { lat: 43.6532, lon: -79.3832, country: 'CA' },
  'São Paulo': { lat: -23.5505, lon: -46.6333, country: 'BR' },
  Mumbai: { lat: 19.076, lon: 72.8777, country: 'IN' },
  Delhi: { lat: 28.7041, lon: 77.1025, country: 'IN' },
  Seoul: { lat: 37.5665, lon: 126.978, country: 'KR' },
  Singapore: { lat: 1.3521, lon: 103.8198, country: 'SG' },
  'Hong Kong': { lat: 22.3193, lon: 114.1694, country: 'HK' },
  Amsterdam: { lat: 52.3676, lon: 4.9041, country: 'NL' },
  Frankfurt: { lat: 50.1109, lon: 8.6821, country: 'DE' },
  Kyiv: { lat: 50.4501, lon: 30.5234, country: 'UA' },
  Tehran: { lat: 35.6892, lon: 51.389, country: 'IR' },
  Istanbul: { lat: 41.0082, lon: 28.9784, country: 'TR' },
}

/**
 * Get coordinates for a location string (country code, country name, or city).
 * @param {string} location - Location string
 * @returns {Object|null} - { lat, lon, name } or null if not found
 */
export function getCoordinates(location) {
  if (!location) return null

  const normalized = location.trim()

  // Try country code first (2-letter)
  if (normalized.length === 2) {
    const upper = normalized.toUpperCase()
    if (COUNTRY_COORDINATES[upper]) {
      return COUNTRY_COORDINATES[upper]
    }
  }

  // Try city name
  if (CITY_COORDINATES[normalized]) {
    const city = CITY_COORDINATES[normalized]
    return { lat: city.lat, lon: city.lon, name: normalized }
  }

  // Try country name (partial match)
  for (const [code, data] of Object.entries(COUNTRY_COORDINATES)) {
    if (data.name.toLowerCase().includes(normalized.toLowerCase())) {
      return data
    }
  }

  return null
}

/**
 * Aggregate attacks by geographic location.
 * @param {Array} attacks - Array of attack objects with location info
 * @returns {Array} - Aggregated location data with counts
 */
export function aggregateByLocation(attacks) {
  if (!attacks || attacks.length === 0) return []

  const locationMap = new Map()

  attacks.forEach((attack) => {
    const location = attack.source_country || attack.location || attack.country
    if (!location) return

    const coords = getCoordinates(location)
    if (!coords) return

    const key = `${coords.lat},${coords.lon}`

    if (!locationMap.has(key)) {
      locationMap.set(key, {
        lat: coords.lat,
        lon: coords.lon,
        name: coords.name || location,
        attacks: [],
        count: 0,
        severity: { critical: 0, high: 0, medium: 0, low: 0 },
        attackTypes: new Set(),
        ips: new Set(),
      })
    }

    const loc = locationMap.get(key)
    loc.attacks.push(attack)
    loc.count++
    if (attack.severity) {
      loc.severity[attack.severity] = (loc.severity[attack.severity] || 0) + 1
    }
    if (attack.attack_type) {
      loc.attackTypes.add(attack.attack_type)
    }
    if (attack.source_ip) {
      loc.ips.add(attack.source_ip)
    }
  })

  // Convert to array and calculate marker sizes
  const result = Array.from(locationMap.values()).map((loc) => ({
    ...loc,
    attackTypes: Array.from(loc.attackTypes),
    ips: Array.from(loc.ips),
    maxSeverity: loc.severity.critical > 0
      ? 'critical'
      : loc.severity.high > 0
      ? 'high'
      : loc.severity.medium > 0
      ? 'medium'
      : 'low',
  }))

  // Sort by count descending
  return result.sort((a, b) => b.count - a.count)
}

/**
 * Calculate marker size based on attack count.
 * @param {number} count - Number of attacks
 * @param {number} maxCount - Maximum count in dataset
 * @param {Object} options - Size options
 * @returns {number} - Marker radius
 */
export function calculateMarkerSize(count, maxCount, options = {}) {
  const { minSize = 4, maxSize = 20 } = options

  if (maxCount === 0) return minSize

  // Use sqrt scale for better visual distribution
  const scale = Math.sqrt(count / maxCount)
  return minSize + scale * (maxSize - minSize)
}

/**
 * Convert lat/lon to SVG coordinates using Mercator projection.
 * @param {number} lat - Latitude
 * @param {number} lon - Longitude
 * @param {Object} viewport - SVG viewport dimensions
 * @returns {Object} - { x, y } coordinates
 */
export function latLonToSvg(lat, lon, viewport = { width: 800, height: 400 }) {
  const { width, height } = viewport

  // Simple equirectangular projection
  const x = ((lon + 180) / 360) * width
  const y = ((90 - lat) / 180) * height

  return { x, y }
}

/**
 * Get the dominant severity from a set of attacks.
 * @param {Object} severityCounts - { critical, high, medium, low }
 * @returns {string} - Dominant severity level
 */
export function getDominantSeverity(severityCounts) {
  if (severityCounts.critical > 0) return 'critical'
  if (severityCounts.high > 0) return 'high'
  if (severityCounts.medium > 0) return 'medium'
  return 'low'
}

export { COUNTRY_COORDINATES, CITY_COORDINATES }
