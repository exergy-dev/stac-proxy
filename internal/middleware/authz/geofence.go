// Package authz provides authorization middleware.
package authz

import (
	"context"
	"errors"

	"github.com/yourorg/stac-proxy/internal/geo"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
)

// Geofencer provides geospatial authorization.
type Geofencer struct {
	userRegions     map[string]*geo.Geometry // userID -> allowed region
	roleRegions     map[string]*geo.Geometry // role -> allowed region
	defaultRegion   *geo.Geometry
	deniedRegions   []*geo.Geometry
	filterMode      bool
	spatialIndex    *geo.SpatialIndex
}

// GeofencerConfig configures the geofencer.
type GeofencerConfig struct {
	UserRegions     map[string]interface{}  // userID -> GeoJSON
	RoleRegions     map[string]interface{}  // role -> GeoJSON
	DefaultRegion   interface{}             // Default allowed GeoJSON
	DeniedRegions   []interface{}           // Globally denied areas
	FilterMode      bool                    // Filter results vs reject requests
	RegionsFile     string                  // Path to regions GeoJSON file
}

// NewGeofencer creates a new geofencer.
func NewGeofencer(cfg GeofencerConfig) (*Geofencer, error) {
	g := &Geofencer{
		userRegions:   make(map[string]*geo.Geometry),
		roleRegions:   make(map[string]*geo.Geometry),
		filterMode:    cfg.FilterMode,
		spatialIndex:  geo.NewSpatialIndex(),
	}

	// Parse user regions
	for userID, geojson := range cfg.UserRegions {
		geom, err := geo.ParseGeoJSON(geojson)
		if err != nil {
			return nil, err
		}
		g.userRegions[userID] = geom
	}

	// Parse role regions
	for role, geojson := range cfg.RoleRegions {
		geom, err := geo.ParseGeoJSON(geojson)
		if err != nil {
			return nil, err
		}
		g.roleRegions[role] = geom
	}

	// Parse default region
	if cfg.DefaultRegion != nil {
		geom, err := geo.ParseGeoJSON(cfg.DefaultRegion)
		if err != nil {
			return nil, err
		}
		g.defaultRegion = geom
	}

	// Parse denied regions
	for _, geojson := range cfg.DeniedRegions {
		geom, err := geo.ParseGeoJSON(geojson)
		if err != nil {
			return nil, err
		}
		g.deniedRegions = append(g.deniedRegions, geom)
	}

	return g, nil
}

// GetEffectiveRegion determines the allowed region for a principal.
func (g *Geofencer) GetEffectiveRegion(principal *auth.Principal) *geo.Geometry {
	if principal == nil {
		return g.defaultRegion
	}

	// Check user-specific region first
	if region, ok := g.userRegions[principal.ID]; ok {
		return region
	}

	// Check role-based regions
	for _, role := range principal.Roles {
		if region, ok := g.roleRegions[role]; ok {
			return region
		}
	}

	// Fall back to default
	return g.defaultRegion
}

// ValidateRequest checks if a search request is within allowed region.
func (g *Geofencer) ValidateRequest(ctx context.Context, req *middleware.STACRequest, principal *auth.Principal) error {
	allowedRegion := g.GetEffectiveRegion(principal)
	if allowedRegion == nil {
		// No geofence constraint
		return nil
	}

	// Extract spatial extent from request
	requestGeom, err := extractRequestGeometry(req)
	if err != nil {
		return err
	}

	if requestGeom == nil {
		// No spatial constraint in request - check if that's allowed
		// For now, allow requests without spatial constraint
		return nil
	}

	// Check if request is within allowed region
	if !allowedRegion.Contains(requestGeom) && !allowedRegion.Intersects(requestGeom) {
		return errors.New("request area is outside allowed region")
	}

	// Check denied regions
	for _, denied := range g.deniedRegions {
		if denied.Intersects(requestGeom) {
			return errors.New("request area intersects denied region")
		}
	}

	return nil
}

// FilterResults filters search results to only include items within allowed region.
func (g *Geofencer) FilterResults(items []interface{}, principal *auth.Principal) []interface{} {
	allowedRegion := g.GetEffectiveRegion(principal)
	if allowedRegion == nil {
		return items
	}

	var filtered []interface{}
	for _, item := range items {
		itemGeom := extractItemGeometry(item)
		if itemGeom == nil {
			continue
		}

		// Check if item is within allowed region
		if !allowedRegion.Intersects(itemGeom) {
			continue
		}

		// Check denied regions
		denied := false
		for _, deniedRegion := range g.deniedRegions {
			if deniedRegion.Contains(itemGeom) {
				denied = true
				break
			}
		}
		if denied {
			continue
		}

		filtered = append(filtered, item)
	}

	return filtered
}

// extractRequestGeometry extracts geometry from a STAC request.
func extractRequestGeometry(req *middleware.STACRequest) (*geo.Geometry, error) {
	// Check for bbox parameter
	if bbox, ok := req.Params["bbox"]; ok {
		return geo.BboxToGeometry(bbox)
	}

	// Check for intersects parameter
	if intersects, ok := req.Params["intersects"]; ok {
		return geo.ParseGeoJSON(intersects)
	}

	return nil, nil
}

// extractItemGeometry extracts geometry from a STAC item.
func extractItemGeometry(item interface{}) *geo.Geometry {
	itemMap, ok := item.(map[string]interface{})
	if !ok {
		return nil
	}

	geomData, ok := itemMap["geometry"]
	if !ok {
		return nil
	}

	geom, err := geo.ParseGeoJSON(geomData)
	if err != nil {
		return nil
	}

	return geom
}

// GeofenceEnforcer wraps Geofencer as an Enforcer.
type GeofenceEnforcer struct {
	geofencer *Geofencer
	name      string
}

// NewGeofenceEnforcer creates an enforcer from a geofencer.
func NewGeofenceEnforcer(name string, geofencer *Geofencer) *GeofenceEnforcer {
	return &GeofenceEnforcer{
		geofencer: geofencer,
		name:      name,
	}
}

// Name returns the enforcer name.
func (e *GeofenceEnforcer) Name() string {
	return e.name
}

// Authorize checks geofence constraints.
func (e *GeofenceEnforcer) Authorize(ctx context.Context, input *AuthzInput) (*AuthzDecision, error) {
	// Build a minimal principal from input
	var principal *auth.Principal
	if input.Principal != nil {
		principal = &auth.Principal{
			ID:    input.Principal.ID,
			Roles: input.Principal.Roles,
		}
	}

	allowedRegion := e.geofencer.GetEffectiveRegion(principal)

	decision := &AuthzDecision{
		Allowed: true,
		Reasons: []string{"geofence check passed"},
	}

	if allowedRegion != nil {
		// Add geofence constraint for downstream filtering
		decision.Constraints = &AuthzConstraints{
			Geofence: &GeofenceConstraint{
				AllowedArea: allowedRegion.ToGeoJSON(),
				FilterMode:  e.geofencer.filterMode,
			},
		}
	}

	return decision, nil
}
