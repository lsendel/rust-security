import { useEffect, useRef, useState } from 'react'
import { MapContainer, TileLayer, CircleMarker, Popup, useMap } from 'react-leaflet'
import { LatLngBounds } from 'leaflet'
import { ThreatEvent } from '@/types/security'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { formatRelativeTime, getSecurityColor } from '@/lib/utils'
import 'leaflet/dist/leaflet.css'

interface ThreatMapProps {
  threats: ThreatEvent[]
}

// Component to auto-fit map bounds
function MapBounds({ threats }: { threats: ThreatEvent[] }) {
  const map = useMap()

  useEffect(() => {
    if (threats.length > 0) {
      const validThreats = threats.filter(threat => threat.geolocation)
      if (validThreats.length > 0) {
        const bounds = new LatLngBounds(
          validThreats.map(threat => [
            threat.geolocation!.lat,
            threat.geolocation!.lng
          ])
        )
        map.fitBounds(bounds, { padding: [20, 20] })
      }
    }
  }, [threats, map])

  return null
}

export function ThreatMapVisualization({ threats }: ThreatMapProps) {
  const [selectedThreat, setSelectedThreat] = useState<ThreatEvent | null>(null)
  const mapRef = useRef<any>(null)

  // Filter threats with geolocation data
  const geoThreats = threats.filter(threat => threat.geolocation)

  // Aggregate threats by location for better visualization
  const aggregatedThreats = geoThreats.reduce((acc, threat) => {
    const key = `${threat.geolocation!.lat}-${threat.geolocation!.lng}`
    if (!acc[key]) {
      acc[key] = {
        ...threat,
        count: 1,
        severities: [threat.severity]
      }
    } else {
      acc[key].count++
      acc[key].severities.push(threat.severity)
      // Use highest severity for display
      if (threat.severity === 'critical' || 
          (threat.severity === 'high' && acc[key].severity !== 'critical')) {
        acc[key].severity = threat.severity
      }
    }
    return acc
  }, {} as Record<string, ThreatEvent & { count: number; severities: string[] }>)

  const threatMarkers = Object.values(aggregatedThreats)

  const getMarkerColor = (severity: string) => {
    switch (severity) {
      case 'critical': return '#ef4444'
      case 'high': return '#f97316'
      case 'medium': return '#eab308'
      case 'low': return '#22c55e'
      default: return '#3b82f6'
    }
  }

  const getMarkerSize = (count: number) => {
    return Math.min(Math.max(count * 5, 10), 50)
  }

  // Threat statistics
  const threatStats = {
    total: threats.length,
    critical: threats.filter(t => t.severity === 'critical').length,
    high: threats.filter(t => t.severity === 'high').length,
    medium: threats.filter(t => t.severity === 'medium').length,
    low: threats.filter(t => t.severity === 'low').length,
    countries: new Set(geoThreats.map(t => t.geolocation?.country).filter(Boolean)).size,
  }

  if (geoThreats.length === 0) {
    return (
      <Card className="h-96 flex items-center justify-center">
        <CardContent>
          <div className="text-center text-muted-foreground">
            <div className="text-lg mb-2">No Geographic Threat Data</div>
            <div className="text-sm">
              Threat events with location data will appear here
            </div>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-4">
      {/* Threat Statistics */}
      <div className="grid grid-cols-6 gap-2">
        <Card className="glass-effect">
          <CardContent className="p-3 text-center">
            <div className="text-lg font-bold">{threatStats.total}</div>
            <div className="text-xs text-muted-foreground">Total</div>
          </CardContent>
        </Card>
        <Card className="glass-effect">
          <CardContent className="p-3 text-center">
            <div className="text-lg font-bold text-red-500">{threatStats.critical}</div>
            <div className="text-xs text-muted-foreground">Critical</div>
          </CardContent>
        </Card>
        <Card className="glass-effect">
          <CardContent className="p-3 text-center">
            <div className="text-lg font-bold text-orange-500">{threatStats.high}</div>
            <div className="text-xs text-muted-foreground">High</div>
          </CardContent>
        </Card>
        <Card className="glass-effect">
          <CardContent className="p-3 text-center">
            <div className="text-lg font-bold text-yellow-500">{threatStats.medium}</div>
            <div className="text-xs text-muted-foreground">Medium</div>
          </CardContent>
        </Card>
        <Card className="glass-effect">
          <CardContent className="p-3 text-center">
            <div className="text-lg font-bold text-green-500">{threatStats.low}</div>
            <div className="text-xs text-muted-foreground">Low</div>
          </CardContent>
        </Card>
        <Card className="glass-effect">
          <CardContent className="p-3 text-center">
            <div className="text-lg font-bold text-blue-500">{threatStats.countries}</div>
            <div className="text-xs text-muted-foreground">Countries</div>
          </CardContent>
        </Card>
      </div>

      {/* Map */}
      <Card className="h-96">
        <CardHeader className="pb-2">
          <CardTitle className="text-lg">Global Threat Distribution</CardTitle>
          <CardDescription>
            Geographic visualization of security threats (marker size indicates frequency)
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="h-80 w-full">
            <MapContainer
              ref={mapRef}
              center={[40, 0]}
              zoom={2}
              style={{ height: '100%', width: '100%' }}
              className="rounded-b-lg"
            >
              <TileLayer
                attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
              />
              
              <MapBounds threats={geoThreats} />
              
              {threatMarkers.map((threat) => (
                <CircleMarker
                  key={threat.id}
                  center={[threat.geolocation!.lat, threat.geolocation!.lng]}
                  radius={getMarkerSize(threat.count)}
                  pathOptions={{
                    color: getMarkerColor(threat.severity),
                    fillColor: getMarkerColor(threat.severity),
                    fillOpacity: 0.6,
                    weight: 2,
                  }}
                  eventHandlers={{
                    click: () => setSelectedThreat(threat),
                  }}
                >
                  <Popup>
                    <div className="space-y-2">
                      <div className="flex items-center gap-2">
                        <Badge 
                          variant={threat.severity === 'critical' ? 'destructive' : 'outline'}
                        >
                          {threat.severity}
                        </Badge>
                        <span className="text-sm font-medium">{threat.type}</span>
                      </div>
                      <div className="text-sm space-y-1">
                        <div><strong>Location:</strong> {threat.geolocation?.city}, {threat.geolocation?.country}</div>
                        <div><strong>Source IP:</strong> {threat.sourceIp}</div>
                        <div><strong>Count:</strong> {threat.count} threats</div>
                        <div><strong>Time:</strong> {formatRelativeTime(threat.timestamp)}</div>
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {threat.description}
                      </div>
                    </div>
                  </Popup>
                </CircleMarker>
              ))}
            </MapContainer>
          </div>
        </CardContent>
      </Card>

      {/* Selected Threat Details */}
      {selectedThreat && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              Threat Details
              <Badge 
                variant={selectedThreat.severity === 'critical' ? 'destructive' : 'outline'}
              >
                {selectedThreat.severity}
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <div><strong>Type:</strong> {selectedThreat.type}</div>
                <div><strong>Source:</strong> {selectedThreat.source}</div>
                <div><strong>IP Address:</strong> {selectedThreat.sourceIp}</div>
                <div><strong>Risk Score:</strong> {selectedThreat.riskScore}/100</div>
              </div>
              <div className="space-y-2">
                <div><strong>Location:</strong> {selectedThreat.geolocation?.city}, {selectedThreat.geolocation?.country}</div>
                <div><strong>Status:</strong> {selectedThreat.status}</div>
                <div><strong>Time:</strong> {formatRelativeTime(selectedThreat.timestamp)}</div>
                {selectedThreat.assignedTo && (
                  <div><strong>Assigned to:</strong> {selectedThreat.assignedTo}</div>
                )}
              </div>
            </div>
            <div className="mt-4">
              <strong>Description:</strong>
              <p className="text-sm text-muted-foreground mt-1">
                {selectedThreat.description}
              </p>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}