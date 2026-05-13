package authz

import (
	"context"
	"testing"

	"github.com/yourorg/stac-proxy/internal/geo"
	"github.com/yourorg/stac-proxy/internal/middleware"
	"github.com/yourorg/stac-proxy/internal/middleware/auth"
)

func TestNewGeofencer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		config    GeofencerConfig
		wantErr   bool
		errString string
		validate  func(*testing.T, *Geofencer)
	}{
		{
			name: "empty config",
			config: GeofencerConfig{
				FilterMode: false,
			},
			wantErr: false,
			validate: func(t *testing.T, g *Geofencer) {
				if g == nil {
					t.Fatal("expected non-nil geofencer")
				}
				if g.filterMode != false {
					t.Errorf("expected filterMode=false, got %v", g.filterMode)
				}
				if g.userRegions == nil {
					t.Error("expected initialized userRegions map")
				}
				if g.roleRegions == nil {
					t.Error("expected initialized roleRegions map")
				}
			},
		},
		{
			name: "with user regions",
			config: GeofencerConfig{
				UserRegions: map[string]interface{}{
					"user1": map[string]interface{}{
						"type": "Polygon",
						"coordinates": [][][]float64{
							{{-10, -10}, {10, -10}, {10, 10}, {-10, 10}, {-10, -10}},
						},
					},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, g *Geofencer) {
				if len(g.userRegions) != 1 {
					t.Errorf("expected 1 user region, got %d", len(g.userRegions))
				}
				if _, ok := g.userRegions["user1"]; !ok {
					t.Error("expected user1 region to be present")
				}
			},
		},
		{
			name: "with role regions",
			config: GeofencerConfig{
				RoleRegions: map[string]interface{}{
					"admin": map[string]interface{}{
						"type": "Polygon",
						"coordinates": [][][]float64{
							{{-180, -90}, {180, -90}, {180, 90}, {-180, 90}, {-180, -90}},
						},
					},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, g *Geofencer) {
				if len(g.roleRegions) != 1 {
					t.Errorf("expected 1 role region, got %d", len(g.roleRegions))
				}
				if _, ok := g.roleRegions["admin"]; !ok {
					t.Error("expected admin role region to be present")
				}
			},
		},
		{
			name: "with default region",
			config: GeofencerConfig{
				DefaultRegion: map[string]interface{}{
					"type": "Polygon",
					"coordinates": [][][]float64{
						{{-10, -10}, {10, -10}, {10, 10}, {-10, 10}, {-10, -10}},
					},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, g *Geofencer) {
				if g.defaultRegion == nil {
					t.Error("expected default region to be set")
				}
			},
		},
		{
			name: "with denied regions",
			config: GeofencerConfig{
				DeniedRegions: []interface{}{
					map[string]interface{}{
						"type": "Polygon",
						"coordinates": [][][]float64{
							{{0, 0}, {5, 0}, {5, 5}, {0, 5}, {0, 0}},
						},
					},
				},
			},
			wantErr: false,
			validate: func(t *testing.T, g *Geofencer) {
				if len(g.deniedRegions) != 1 {
					t.Errorf("expected 1 denied region, got %d", len(g.deniedRegions))
				}
			},
		},
		{
			name: "filter mode enabled",
			config: GeofencerConfig{
				FilterMode: true,
			},
			wantErr: false,
			validate: func(t *testing.T, g *Geofencer) {
				if !g.filterMode {
					t.Error("expected filterMode to be true")
				}
			},
		},
		{
			name: "invalid user region geojson",
			config: GeofencerConfig{
				UserRegions: map[string]interface{}{
					"user1": "invalid geojson",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid role region geojson",
			config: GeofencerConfig{
				RoleRegions: map[string]interface{}{
					"admin": 12345,
				},
			},
			wantErr: true,
		},
		{
			name: "multiple regions complex config",
			config: GeofencerConfig{
				UserRegions: map[string]interface{}{
					"user1": map[string]interface{}{
						"type":        "Polygon",
						"coordinates": [][][]float64{{{-10, -10}, {10, -10}, {10, 10}, {-10, 10}, {-10, -10}}},
					},
					"user2": map[string]interface{}{
						"type":        "Polygon",
						"coordinates": [][][]float64{{{-20, -20}, {20, -20}, {20, 20}, {-20, 20}, {-20, -20}}},
					},
				},
				RoleRegions: map[string]interface{}{
					"viewer": map[string]interface{}{
						"type":        "Polygon",
						"coordinates": [][][]float64{{{-50, -50}, {50, -50}, {50, 50}, {-50, 50}, {-50, -50}}},
					},
				},
				DefaultRegion: map[string]interface{}{
					"type":        "Polygon",
					"coordinates": [][][]float64{{{-5, -5}, {5, -5}, {5, 5}, {-5, 5}, {-5, -5}}},
				},
				DeniedRegions: []interface{}{
					map[string]interface{}{
						"type":        "Polygon",
						"coordinates": [][][]float64{{{0, 0}, {1, 0}, {1, 1}, {0, 1}, {0, 0}}},
					},
				},
				FilterMode: true,
			},
			wantErr: false,
			validate: func(t *testing.T, g *Geofencer) {
				if len(g.userRegions) != 2 {
					t.Errorf("expected 2 user regions, got %d", len(g.userRegions))
				}
				if len(g.roleRegions) != 1 {
					t.Errorf("expected 1 role region, got %d", len(g.roleRegions))
				}
				if g.defaultRegion == nil {
					t.Error("expected default region")
				}
				if len(g.deniedRegions) != 1 {
					t.Errorf("expected 1 denied region, got %d", len(g.deniedRegions))
				}
				if !g.filterMode {
					t.Error("expected filter mode to be enabled")
				}
			},
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			g, err := NewGeofencer(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewGeofencer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.errString != "" && err.Error() != tt.errString {
				t.Errorf("NewGeofencer() error = %v, want %v", err.Error(), tt.errString)
			}

			if !tt.wantErr && tt.validate != nil {
				tt.validate(t, g)
			}
		})
	}
}

func TestGetEffectiveRegion(t *testing.T) {
	t.Parallel()

	// Setup test geofencer with user, role, and default regions
	config := GeofencerConfig{
		UserRegions: map[string]interface{}{
			"user123": map[string]interface{}{
				"type":        "Polygon",
				"coordinates": [][][]float64{{{-10, -10}, {10, -10}, {10, 10}, {-10, 10}, {-10, -10}}},
			},
		},
		RoleRegions: map[string]interface{}{
			"admin": map[string]interface{}{
				"type":        "Polygon",
				"coordinates": [][][]float64{{{-100, -100}, {100, -100}, {100, 100}, {-100, 100}, {-100, -100}}},
			},
			"viewer": map[string]interface{}{
				"type":        "Polygon",
				"coordinates": [][][]float64{{{-50, -50}, {50, -50}, {50, 50}, {-50, 50}, {-50, -50}}},
			},
		},
		DefaultRegion: map[string]interface{}{
			"type":        "Polygon",
			"coordinates": [][][]float64{{{-5, -5}, {5, -5}, {5, 5}, {-5, 5}, {-5, -5}}},
		},
	}

	g, err := NewGeofencer(config)
	if err != nil {
		t.Fatalf("failed to create geofencer: %v", err)
	}

	tests := []struct {
		name      string
		principal *auth.Principal
		wantNil   bool
		validate  func(*testing.T, *geo.Geometry)
	}{
		{
			name:      "nil principal returns default",
			principal: nil,
			wantNil:   false,
			validate: func(t *testing.T, geom *geo.Geometry) {
				if geom == nil {
					t.Error("expected default region, got nil")
				}
			},
		},
		{
			name: "user-specific region takes precedence",
			principal: &auth.Principal{
				ID:    "user123",
				Roles: []string{"viewer", "admin"},
			},
			wantNil: false,
			validate: func(t *testing.T, geom *geo.Geometry) {
				if geom == nil {
					t.Error("expected user region, got nil")
				}
				// User region should be returned, not role or default
			},
		},
		{
			name: "role-based region when no user region",
			principal: &auth.Principal{
				ID:    "user999",
				Roles: []string{"admin"},
			},
			wantNil: false,
			validate: func(t *testing.T, geom *geo.Geometry) {
				if geom == nil {
					t.Error("expected admin role region, got nil")
				}
			},
		},
		{
			name: "first role wins when multiple roles",
			principal: &auth.Principal{
				ID:    "user999",
				Roles: []string{"admin", "viewer"},
			},
			wantNil: false,
			validate: func(t *testing.T, geom *geo.Geometry) {
				if geom == nil {
					t.Error("expected role region, got nil")
				}
			},
		},
		{
			name: "default region when no user or role match",
			principal: &auth.Principal{
				ID:    "user999",
				Roles: []string{"unknown"},
			},
			wantNil: false,
			validate: func(t *testing.T, geom *geo.Geometry) {
				if geom == nil {
					t.Error("expected default region, got nil")
				}
			},
		},
		{
			name: "user with no roles gets default",
			principal: &auth.Principal{
				ID:    "user888",
				Roles: []string{},
			},
			wantNil: false,
			validate: func(t *testing.T, geom *geo.Geometry) {
				if geom == nil {
					t.Error("expected default region, got nil")
				}
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			region := g.GetEffectiveRegion(tt.principal)

			if tt.wantNil && region != nil {
				t.Errorf("GetEffectiveRegion() = %v, want nil", region)
			}

			if !tt.wantNil && region == nil {
				t.Error("GetEffectiveRegion() = nil, want non-nil")
			}

			if tt.validate != nil {
				tt.validate(t, region)
			}
		})
	}
}

func TestGetEffectiveRegion_NoDefaultRegion(t *testing.T) {
	t.Parallel()

	// Geofencer with no default region
	config := GeofencerConfig{
		UserRegions: map[string]interface{}{
			"user1": map[string]interface{}{
				"type":        "Polygon",
				"coordinates": [][][]float64{{{0, 0}, {10, 0}, {10, 10}, {0, 10}, {0, 0}}},
			},
		},
	}

	g, err := NewGeofencer(config)
	if err != nil {
		t.Fatalf("failed to create geofencer: %v", err)
	}

	t.Run("nil principal returns nil when no default", func(t *testing.T) {
		region := g.GetEffectiveRegion(nil)
		if region != nil {
			t.Errorf("expected nil region, got %v", region)
		}
	})

	t.Run("unknown user returns nil when no default", func(t *testing.T) {
		principal := &auth.Principal{
			ID:    "unknown",
			Roles: []string{},
		}
		region := g.GetEffectiveRegion(principal)
		if region != nil {
			t.Errorf("expected nil region, got %v", region)
		}
	})
}

func TestValidateRequest(t *testing.T) {
	t.Parallel()

	config := GeofencerConfig{
		UserRegions: map[string]interface{}{
			"user1": map[string]interface{}{
				"type":        "Polygon",
				"coordinates": [][][]float64{{{-10, -10}, {10, -10}, {10, 10}, {-10, 10}, {-10, -10}}},
			},
		},
		DefaultRegion: map[string]interface{}{
			"type":        "Polygon",
			"coordinates": [][][]float64{{{-5, -5}, {5, -5}, {5, 5}, {-5, 5}, {-5, -5}}},
		},
		DeniedRegions: []interface{}{
			map[string]interface{}{
				"type":        "Polygon",
				"coordinates": [][][]float64{{{100, 100}, {110, 100}, {110, 110}, {100, 110}, {100, 100}}},
			},
		},
	}

	g, err := NewGeofencer(config)
	if err != nil {
		t.Fatalf("failed to create geofencer: %v", err)
	}

	tests := []struct {
		name      string
		req       *middleware.STACRequest
		principal *auth.Principal
		wantErr   bool
		errMsg    string
	}{
		{
			name: "no geofence constraint allows any request",
			req: &middleware.STACRequest{
				Params: map[string]interface{}{},
			},
			principal: nil, // Will get default region in this case
			wantErr:   false,
		},
		{
			name: "request with no spatial constraint is allowed",
			req: &middleware.STACRequest{
				Params: map[string]interface{}{
					"collections": []string{"test"},
				},
			},
			principal: &auth.Principal{
				ID:    "user1",
				Roles: []string{},
			},
			wantErr: false,
		},
		{
			name: "bbox within allowed region",
			req: &middleware.STACRequest{
				Params: map[string]interface{}{
					"bbox": []float64{-5, -5, 5, 5},
				},
			},
			principal: &auth.Principal{
				ID:    "user1",
				Roles: []string{},
			},
			wantErr: false,
		},
		{
			name: "bbox partially outside allowed region",
			req: &middleware.STACRequest{
				Params: map[string]interface{}{
					"bbox": []float64{-15, -15, 15, 15},
				},
			},
			principal: &auth.Principal{
				ID:    "user1",
				Roles: []string{},
			},
			wantErr: true, // request escapes the allowed region → rejected
		},
		{
			name: "bbox completely outside allowed region",
			req: &middleware.STACRequest{
				Params: map[string]interface{}{
					"bbox": []float64{50, 50, 60, 60},
				},
			},
			principal: &auth.Principal{
				ID:    "user1",
				Roles: []string{},
			},
			wantErr: true,
			errMsg:  "request area is outside allowed region",
		},
		{
			name: "intersects geometry within allowed region",
			req: &middleware.STACRequest{
				Params: map[string]interface{}{
					"intersects": map[string]interface{}{
						"type":        "Polygon",
						"coordinates": [][][]float64{{{-3, -3}, {3, -3}, {3, 3}, {-3, 3}, {-3, -3}}},
					},
				},
			},
			principal: &auth.Principal{
				ID:    "user1",
				Roles: []string{},
			},
			wantErr: false,
		},
		{
			name: "intersects geometry outside allowed region",
			req: &middleware.STACRequest{
				Params: map[string]interface{}{
					"intersects": map[string]interface{}{
						"type":        "Polygon",
						"coordinates": [][][]float64{{{50, 50}, {60, 50}, {60, 60}, {50, 60}, {50, 50}}},
					},
				},
			},
			principal: &auth.Principal{
				ID:    "user1",
				Roles: []string{},
			},
			wantErr: true,
			errMsg:  "request area is outside allowed region",
		},
		{
			name: "request intersects denied region",
			req: &middleware.STACRequest{
				Params: map[string]interface{}{
					"bbox": []float64{100, 100, 110, 110},
				},
			},
			principal: nil, // Will try to use default region
			wantErr:   true,
			errMsg:    "request area is outside allowed region", // First fails the allowed region check
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Note: Not using t.Parallel() here because we're using a shared geofencer

			ctx := context.Background()
			err := g.ValidateRequest(ctx, tt.req, tt.principal)

			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.errMsg != "" && err.Error() != tt.errMsg {
				t.Errorf("ValidateRequest() error = %v, want %v", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestValidateRequest_NilAllowedRegion(t *testing.T) {
	t.Parallel()

	// Geofencer with no regions
	g, err := NewGeofencer(GeofencerConfig{})
	if err != nil {
		t.Fatalf("failed to create geofencer: %v", err)
	}

	req := &middleware.STACRequest{
		Params: map[string]interface{}{
			"bbox": []float64{-180, -90, 180, 90},
		},
	}

	err = g.ValidateRequest(context.Background(), req, nil)
	if err != nil {
		t.Errorf("ValidateRequest() with nil allowed region should not error, got: %v", err)
	}
}

func TestFilterResults(t *testing.T) {
	t.Parallel()

	config := GeofencerConfig{
		UserRegions: map[string]interface{}{
			"user1": map[string]interface{}{
				"type":        "Polygon",
				"coordinates": [][][]float64{{{-10, -10}, {10, -10}, {10, 10}, {-10, 10}, {-10, -10}}},
			},
		},
		DeniedRegions: []interface{}{
			map[string]interface{}{
				"type":        "Polygon",
				"coordinates": [][][]float64{{{0, 0}, {5, 0}, {5, 5}, {0, 5}, {0, 0}}},
			},
		},
	}

	g, err := NewGeofencer(config)
	if err != nil {
		t.Fatalf("failed to create geofencer: %v", err)
	}

	tests := []struct {
		name      string
		items     []interface{}
		principal *auth.Principal
		wantCount int
	}{
		{
			name:      "nil allowed region returns all items",
			items:     makeTestItems(5),
			principal: nil, // No region assigned
			wantCount: 5,
		},
		{
			name: "filters items outside allowed region",
			items: []interface{}{
				map[string]interface{}{
					"id": "item1",
					"geometry": map[string]interface{}{
						"type":        "Point",
						"coordinates": []float64{-3, -3}, // inside allowed, outside denied
					},
				},
				map[string]interface{}{
					"id": "item2",
					"geometry": map[string]interface{}{
						"type":        "Point",
						"coordinates": []float64{50, 50}, // outside allowed
					},
				},
				map[string]interface{}{
					"id": "item3",
					"geometry": map[string]interface{}{
						"type":        "Point",
						"coordinates": []float64{7, 7}, // inside allowed, outside denied
					},
				},
			},
			principal: &auth.Principal{ID: "user1"},
			wantCount: 2, // item1 and item3 should pass, item2 filtered out
		},
		{
			name: "filters items in denied region",
			items: []interface{}{
				map[string]interface{}{
					"id": "item1",
					"geometry": map[string]interface{}{
						"type":        "Point",
						"coordinates": []float64{2, 2}, // In denied region
					},
				},
				map[string]interface{}{
					"id": "item2",
					"geometry": map[string]interface{}{
						"type":        "Point",
						"coordinates": []float64{-5, -5},
					},
				},
			},
			principal: &auth.Principal{ID: "user1"},
			wantCount: 1, // Only item2
		},
		{
			name: "filters items with no geometry",
			items: []interface{}{
				map[string]interface{}{
					"id": "item1",
				},
				map[string]interface{}{
					"id": "item2",
					"geometry": map[string]interface{}{
						"type":        "Point",
						"coordinates": []float64{-3, -3},
					},
				},
			},
			principal: &auth.Principal{ID: "user1"},
			wantCount: 1, // Only item2 has geometry
		},
		{
			name: "filters items with polygon geometry",
			items: []interface{}{
				map[string]interface{}{
					"id": "item1",
					"geometry": map[string]interface{}{
						"type":        "Polygon",
						"coordinates": [][][]float64{{{-2, -2}, {2, -2}, {2, 2}, {-2, 2}, {-2, -2}}},
					},
				},
				map[string]interface{}{
					"id": "item2",
					"geometry": map[string]interface{}{
						"type":        "Polygon",
						"coordinates": [][][]float64{{{50, 50}, {60, 50}, {60, 60}, {50, 60}, {50, 50}}},
					},
				},
			},
			principal: &auth.Principal{ID: "user1"},
			wantCount: 1, // Only item1 intersects allowed region
		},
		{
			name:      "empty items list",
			items:     []interface{}{},
			principal: &auth.Principal{ID: "user1"},
			wantCount: 0,
		},
		{
			name: "invalid item types are filtered",
			items: []interface{}{
				"invalid",
				123,
				map[string]interface{}{
					"id": "valid",
					"geometry": map[string]interface{}{
						"type":        "Point",
						"coordinates": []float64{-3, -3},
					},
				},
			},
			principal: &auth.Principal{ID: "user1"},
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// Not parallel due to shared geofencer

			filtered := g.FilterResults(tt.items, tt.principal)

			if len(filtered) != tt.wantCount {
				t.Errorf("FilterResults() returned %d items, want %d", len(filtered), tt.wantCount)
			}
		})
	}
}

func TestExtractRequestGeometry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		req     *middleware.STACRequest
		wantNil bool
		wantErr bool
	}{
		{
			name: "bbox parameter",
			req: &middleware.STACRequest{
				Params: map[string]interface{}{
					"bbox": []float64{-10, -10, 10, 10},
				},
			},
			wantNil: false,
			wantErr: false,
		},
		{
			name: "intersects parameter",
			req: &middleware.STACRequest{
				Params: map[string]interface{}{
					"intersects": map[string]interface{}{
						"type":        "Polygon",
						"coordinates": [][][]float64{{{0, 0}, {10, 0}, {10, 10}, {0, 10}, {0, 0}}},
					},
				},
			},
			wantNil: false,
			wantErr: false,
		},
		{
			name: "both bbox and intersects - bbox takes precedence",
			req: &middleware.STACRequest{
				Params: map[string]interface{}{
					"bbox": []float64{-5, -5, 5, 5},
					"intersects": map[string]interface{}{
						"type":        "Polygon",
						"coordinates": [][][]float64{{{0, 0}, {10, 0}, {10, 10}, {0, 10}, {0, 0}}},
					},
				},
			},
			wantNil: false,
			wantErr: false,
		},
		{
			name: "no spatial parameters",
			req: &middleware.STACRequest{
				Params: map[string]interface{}{
					"collections": []string{"test"},
				},
			},
			wantNil: true,
			wantErr: false,
		},
		{
			name: "empty params",
			req: &middleware.STACRequest{
				Params: map[string]interface{}{},
			},
			wantNil: true,
			wantErr: false,
		},
		{
			name: "invalid bbox format",
			req: &middleware.STACRequest{
				Params: map[string]interface{}{
					"bbox": "invalid",
				},
			},
			wantNil: true, // Returns nil when conversion fails
			wantErr: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			geom, err := extractRequestGeometry(tt.req)

			if (err != nil) != tt.wantErr {
				t.Errorf("extractRequestGeometry() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if (geom == nil) != tt.wantNil {
				t.Errorf("extractRequestGeometry() geom = %v, wantNil %v", geom, tt.wantNil)
			}
		})
	}
}

func TestExtractItemGeometry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		item    interface{}
		wantNil bool
	}{
		{
			name: "valid item with geometry",
			item: map[string]interface{}{
				"id": "test",
				"geometry": map[string]interface{}{
					"type":        "Point",
					"coordinates": []float64{0, 0},
				},
			},
			wantNil: false,
		},
		{
			name: "item without geometry",
			item: map[string]interface{}{
				"id": "test",
			},
			wantNil: true,
		},
		{
			name:    "non-map item",
			item:    "invalid",
			wantNil: true,
		},
		{
			name:    "nil item",
			item:    nil,
			wantNil: true,
		},
		{
			name: "item with null geometry",
			item: map[string]interface{}{
				"id":       "test",
				"geometry": nil,
			},
			wantNil: true,
		},
		{
			name: "item with polygon geometry",
			item: map[string]interface{}{
				"id": "test",
				"geometry": map[string]interface{}{
					"type":        "Polygon",
					"coordinates": [][][]float64{{{0, 0}, {10, 0}, {10, 10}, {0, 10}, {0, 0}}},
				},
			},
			wantNil: false,
		},
		{
			name: "item with invalid geometry format",
			item: map[string]interface{}{
				"id":       "test",
				"geometry": "invalid",
			},
			wantNil: true, // ParseGeoJSON should fail and return nil
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			geom := extractItemGeometry(tt.item)

			if (geom == nil) != tt.wantNil {
				t.Errorf("extractItemGeometry() geom = %v, wantNil %v", geom, tt.wantNil)
			}
		})
	}
}

func TestGeofenceEnforcer(t *testing.T) {
	t.Parallel()

	config := GeofencerConfig{
		DefaultRegion: map[string]interface{}{
			"type":        "Polygon",
			"coordinates": [][][]float64{{{-10, -10}, {10, -10}, {10, 10}, {-10, 10}, {-10, -10}}},
		},
		FilterMode: true,
	}

	geofencer, err := NewGeofencer(config)
	if err != nil {
		t.Fatalf("failed to create geofencer: %v", err)
	}

	t.Run("NewGeofenceEnforcer", func(t *testing.T) {
		enforcer := NewGeofenceEnforcer("test-geofence", geofencer)

		if enforcer == nil {
			t.Fatal("expected non-nil enforcer")
		}

		if enforcer.geofencer != geofencer {
			t.Error("enforcer geofencer not set correctly")
		}

		if enforcer.name != "test-geofence" {
			t.Errorf("enforcer name = %v, want test-geofence", enforcer.name)
		}
	})

	t.Run("Name", func(t *testing.T) {
		enforcer := NewGeofenceEnforcer("my-geofence", geofencer)
		if enforcer.Name() != "my-geofence" {
			t.Errorf("Name() = %v, want my-geofence", enforcer.Name())
		}
	})

	t.Run("Authorize with nil principal", func(t *testing.T) {
		enforcer := NewGeofenceEnforcer("test", geofencer)

		input := &AuthzInput{
			Principal: nil,
		}

		decision, err := enforcer.Authorize(context.Background(), input)

		if err != nil {
			t.Errorf("Authorize() error = %v, want nil", err)
		}

		if decision == nil {
			t.Fatal("expected non-nil decision")
		}

		if !decision.Allowed {
			t.Error("expected decision to be allowed")
		}

		if len(decision.Reasons) == 0 {
			t.Error("expected decision reasons to be set")
		}
	})

	t.Run("Authorize with principal", func(t *testing.T) {
		enforcer := NewGeofenceEnforcer("test", geofencer)

		input := &AuthzInput{
			Principal: &PrincipalInfo{
				ID:    "user1",
				Roles: []string{"viewer"},
			},
		}

		decision, err := enforcer.Authorize(context.Background(), input)

		if err != nil {
			t.Errorf("Authorize() error = %v, want nil", err)
		}

		if !decision.Allowed {
			t.Error("expected decision to be allowed")
		}
	})

	t.Run("Authorize sets geofence constraint", func(t *testing.T) {
		enforcer := NewGeofenceEnforcer("test", geofencer)

		input := &AuthzInput{
			Principal: &PrincipalInfo{
				ID:    "user1",
				Roles: []string{"viewer"},
			},
		}

		decision, err := enforcer.Authorize(context.Background(), input)

		if err != nil {
			t.Fatalf("Authorize() error = %v", err)
		}

		if decision.Constraints == nil {
			t.Error("expected constraints to be set")
			return
		}

		if decision.Constraints.Geofence == nil {
			t.Error("expected geofence constraint to be set")
			return
		}

		if decision.Constraints.Geofence.AllowedArea == nil {
			t.Error("expected allowed area to be set")
		}

		if !decision.Constraints.Geofence.FilterMode {
			t.Error("expected filter mode to be enabled")
		}
	})

	t.Run("Authorize without allowed region", func(t *testing.T) {
		// Create geofencer with no default region
		noRegionConfig := GeofencerConfig{}
		noRegionGeofencer, err := NewGeofencer(noRegionConfig)
		if err != nil {
			t.Fatalf("failed to create geofencer: %v", err)
		}

		enforcer := NewGeofenceEnforcer("test", noRegionGeofencer)

		input := &AuthzInput{
			Principal: &PrincipalInfo{
				ID: "user1",
			},
		}

		decision, err := enforcer.Authorize(context.Background(), input)

		if err != nil {
			t.Errorf("Authorize() error = %v", err)
		}

		if !decision.Allowed {
			t.Error("expected allowed to be true")
		}

		if decision.Constraints != nil && decision.Constraints.Geofence != nil {
			t.Error("expected no geofence constraint when no region is defined")
		}
	})
}

func TestGeofenceEnforcer_Interface(t *testing.T) {
	t.Parallel()

	// Verify GeofenceEnforcer implements Enforcer interface
	var _ Enforcer = (*GeofenceEnforcer)(nil)
}

func TestFilterMode(t *testing.T) {
	t.Parallel()

	t.Run("filter mode enabled", func(t *testing.T) {
		config := GeofencerConfig{
			FilterMode: true,
			DefaultRegion: map[string]interface{}{
				"type":        "Polygon",
				"coordinates": [][][]float64{{{-10, -10}, {10, -10}, {10, 10}, {-10, 10}, {-10, -10}}},
			},
		}

		g, err := NewGeofencer(config)
		if err != nil {
			t.Fatalf("failed to create geofencer: %v", err)
		}

		if !g.filterMode {
			t.Error("expected filter mode to be enabled")
		}
	})

	t.Run("filter mode disabled (reject mode)", func(t *testing.T) {
		config := GeofencerConfig{
			FilterMode: false,
			DefaultRegion: map[string]interface{}{
				"type":        "Polygon",
				"coordinates": [][][]float64{{{-10, -10}, {10, -10}, {10, 10}, {-10, 10}, {-10, -10}}},
			},
		}

		g, err := NewGeofencer(config)
		if err != nil {
			t.Fatalf("failed to create geofencer: %v", err)
		}

		if g.filterMode {
			t.Error("expected filter mode to be disabled")
		}
	})
}

func TestDeniedRegions(t *testing.T) {
	t.Parallel()

	config := GeofencerConfig{
		DefaultRegion: map[string]interface{}{
			"type":        "Polygon",
			"coordinates": [][][]float64{{{-50, -50}, {50, -50}, {50, 50}, {-50, 50}, {-50, -50}}},
		},
		DeniedRegions: []interface{}{
			map[string]interface{}{
				"type":        "Polygon",
				"coordinates": [][][]float64{{{0, 0}, {10, 0}, {10, 10}, {0, 10}, {0, 0}}},
			},
			map[string]interface{}{
				"type":        "Polygon",
				"coordinates": [][][]float64{{{20, 20}, {30, 20}, {30, 30}, {20, 30}, {20, 20}}},
			},
		},
	}

	g, err := NewGeofencer(config)
	if err != nil {
		t.Fatalf("failed to create geofencer: %v", err)
	}

	t.Run("multiple denied regions stored", func(t *testing.T) {
		if len(g.deniedRegions) != 2 {
			t.Errorf("expected 2 denied regions, got %d", len(g.deniedRegions))
		}
	})

	t.Run("FilterResults excludes items in denied regions", func(t *testing.T) {
		items := []interface{}{
			map[string]interface{}{
				"id": "item1",
				"geometry": map[string]interface{}{
					"type":        "Point",
					"coordinates": []float64{5, 5}, // In first denied region
				},
			},
			map[string]interface{}{
				"id": "item2",
				"geometry": map[string]interface{}{
					"type":        "Point",
					"coordinates": []float64{25, 25}, // In second denied region
				},
			},
			map[string]interface{}{
				"id": "item3",
				"geometry": map[string]interface{}{
					"type":        "Point",
					"coordinates": []float64{-20, -20}, // Not in any denied region
				},
			},
		}

		filtered := g.FilterResults(items, nil)

		if len(filtered) != 1 {
			t.Errorf("expected 1 item after filtering, got %d", len(filtered))
		}

		if len(filtered) > 0 {
			itemMap, ok := filtered[0].(map[string]interface{})
			if !ok {
				t.Fatal("filtered item is not a map")
			}
			if itemMap["id"] != "item3" {
				t.Errorf("expected item3 to pass filter, got %v", itemMap["id"])
			}
		}
	})
}

func TestValidateRequest_EdgeCases(t *testing.T) {
	t.Parallel()

	config := GeofencerConfig{
		DefaultRegion: map[string]interface{}{
			"type":        "Polygon",
			"coordinates": [][][]float64{{{-10, -10}, {10, -10}, {10, 10}, {-10, 10}, {-10, -10}}},
		},
	}

	g, err := NewGeofencer(config)
	if err != nil {
		t.Fatalf("failed to create geofencer: %v", err)
	}

	tests := []struct {
		name      string
		req       *middleware.STACRequest
		principal *auth.Principal
		wantErr   bool
	}{
		{
			name: "nil params map",
			req: &middleware.STACRequest{
				Params: nil,
			},
			principal: &auth.Principal{ID: "user1"},
			wantErr:   false,
		},
		{
			name: "bbox with 6 values (3D)",
			req: &middleware.STACRequest{
				Params: map[string]interface{}{
					"bbox": []float64{-5, -5, 0, 5, 5, 100},
				},
			},
			principal: &auth.Principal{ID: "user1"},
			wantErr:   false,
		},
		{
			name: "intersects with multipolygon",
			req: &middleware.STACRequest{
				Params: map[string]interface{}{
					"intersects": map[string]interface{}{
						"type": "MultiPolygon",
						"coordinates": [][][][]float64{
							{{{0, 0}, {5, 0}, {5, 5}, {0, 5}, {0, 0}}},
						},
					},
				},
			},
			principal: &auth.Principal{ID: "user1"},
			wantErr:   false,
		},
		{
			name: "intersects with point geometry",
			req: &middleware.STACRequest{
				Params: map[string]interface{}{
					"intersects": map[string]interface{}{
						"type":        "Point",
						"coordinates": []float64{0, 0},
					},
				},
			},
			principal: &auth.Principal{ID: "user1"},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := g.ValidateRequest(context.Background(), tt.req, tt.principal)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFilterResults_EdgeCases(t *testing.T) {
	t.Parallel()

	config := GeofencerConfig{
		DefaultRegion: map[string]interface{}{
			"type":        "Polygon",
			"coordinates": [][][]float64{{{-10, -10}, {10, -10}, {10, 10}, {-10, 10}, {-10, -10}}},
		},
	}

	g, err := NewGeofencer(config)
	if err != nil {
		t.Fatalf("failed to create geofencer: %v", err)
	}

	tests := []struct {
		name      string
		items     []interface{}
		principal *auth.Principal
		wantCount int
	}{
		{
			name:      "nil items slice",
			items:     nil,
			principal: &auth.Principal{ID: "user1"},
			wantCount: 0,
		},
		{
			name: "items with multipolygon geometry",
			items: []interface{}{
				map[string]interface{}{
					"id": "item1",
					"geometry": map[string]interface{}{
						"type": "MultiPolygon",
						"coordinates": [][][][]float64{
							{{{0, 0}, {5, 0}, {5, 5}, {0, 5}, {0, 0}}},
						},
					},
				},
			},
			principal: &auth.Principal{ID: "user1"},
			wantCount: 1,
		},
		{
			name: "items with geometry collection",
			items: []interface{}{
				map[string]interface{}{
					"id": "item1",
					"geometry": map[string]interface{}{
						"type": "GeometryCollection",
						"geometries": []interface{}{
							map[string]interface{}{
								"type":        "Point",
								"coordinates": []float64{0, 0},
							},
						},
					},
				},
			},
			principal: &auth.Principal{ID: "user1"},
			wantCount: 1,
		},
		{
			name: "items with invalid geometry are filtered",
			items: []interface{}{
				map[string]interface{}{
					"id": "item1",
					"geometry": map[string]interface{}{
						"type": "InvalidType",
					},
				},
				map[string]interface{}{
					"id": "item2",
					"geometry": map[string]interface{}{
						"type":        "Point",
						"coordinates": []float64{0, 0},
					},
				},
			},
			principal: &auth.Principal{ID: "user1"},
			wantCount: 1, // Only item2 should pass
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			filtered := g.FilterResults(tt.items, tt.principal)
			if len(filtered) != tt.wantCount {
				t.Errorf("FilterResults() returned %d items, want %d", len(filtered), tt.wantCount)
			}
		})
	}
}

func TestGeofenceEnforcer_AuthzInputMapping(t *testing.T) {
	t.Parallel()

	config := GeofencerConfig{
		UserRegions: map[string]interface{}{
			"testuser": map[string]interface{}{
				"type":        "Polygon",
				"coordinates": [][][]float64{{{-10, -10}, {10, -10}, {10, 10}, {-10, 10}, {-10, -10}}},
			},
		},
		FilterMode: false,
	}

	geofencer, err := NewGeofencer(config)
	if err != nil {
		t.Fatalf("failed to create geofencer: %v", err)
	}

	enforcer := NewGeofenceEnforcer("test", geofencer)

	t.Run("maps principal info correctly", func(t *testing.T) {
		input := &AuthzInput{
			Principal: &PrincipalInfo{
				ID:    "testuser",
				Type:  "user",
				Roles: []string{"viewer", "editor"},
				Groups: []string{"team-a"},
				Attributes: map[string]interface{}{
					"dept": "engineering",
				},
			},
		}

		decision, err := enforcer.Authorize(context.Background(), input)
		if err != nil {
			t.Fatalf("Authorize() error = %v", err)
		}

		if !decision.Allowed {
			t.Error("expected allowed=true")
		}

		if decision.Constraints == nil {
			t.Error("expected constraints to be set")
			return
		}

		if decision.Constraints.Geofence == nil {
			t.Error("expected geofence constraint")
			return
		}

		if decision.Constraints.Geofence.FilterMode {
			t.Error("expected FilterMode=false")
		}
	})

	t.Run("handles empty principal", func(t *testing.T) {
		input := &AuthzInput{
			Principal: &PrincipalInfo{
				ID:    "",
				Roles: []string{},
			},
		}

		decision, err := enforcer.Authorize(context.Background(), input)
		if err != nil {
			t.Fatalf("Authorize() error = %v", err)
		}

		if !decision.Allowed {
			t.Error("expected allowed=true")
		}
	})
}

func TestConcurrency(t *testing.T) {
	t.Parallel()

	config := GeofencerConfig{
		DefaultRegion: map[string]interface{}{
			"type":        "Polygon",
			"coordinates": [][][]float64{{{-10, -10}, {10, -10}, {10, 10}, {-10, 10}, {-10, -10}}},
		},
	}

	g, err := NewGeofencer(config)
	if err != nil {
		t.Fatalf("failed to create geofencer: %v", err)
	}

	// Test concurrent access to geofencer
	t.Run("concurrent GetEffectiveRegion", func(t *testing.T) {
		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func(id int) {
				principal := &auth.Principal{
					ID:    "user" + string(rune(id)),
					Roles: []string{"viewer"},
				}
				region := g.GetEffectiveRegion(principal)
				if region == nil {
					t.Error("expected non-nil region")
				}
				done <- true
			}(i)
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	})

	t.Run("concurrent ValidateRequest", func(t *testing.T) {
		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func(id int) {
				req := &middleware.STACRequest{
					Params: map[string]interface{}{
						"bbox": []float64{-5, -5, 5, 5},
					},
				}
				principal := &auth.Principal{
					ID: "user" + string(rune(id)),
				}
				err := g.ValidateRequest(context.Background(), req, principal)
				if err != nil {
					t.Errorf("ValidateRequest() error = %v", err)
				}
				done <- true
			}(i)
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	})

	t.Run("concurrent FilterResults", func(t *testing.T) {
		items := makeTestItems(5)
		done := make(chan bool)

		for i := 0; i < 10; i++ {
			go func(id int) {
				principal := &auth.Principal{
					ID: "user" + string(rune(id)),
				}
				filtered := g.FilterResults(items, principal)
				if filtered == nil {
					t.Error("expected non-nil filtered results")
				}
				done <- true
			}(i)
		}

		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

func TestComplexScenarios(t *testing.T) {
	t.Parallel()

	t.Run("multiple users with different regions", func(t *testing.T) {
		config := GeofencerConfig{
			UserRegions: map[string]interface{}{
				"alice": map[string]interface{}{
					"type":        "Polygon",
					"coordinates": [][][]float64{{{-125, 24}, {-66, 24}, {-66, 50}, {-125, 50}, {-125, 24}}}, // US
				},
				"bob": map[string]interface{}{
					"type":        "Polygon",
					"coordinates": [][][]float64{{{-10, 35}, {40, 35}, {40, 70}, {-10, 70}, {-10, 35}}}, // Europe
				},
			},
			DeniedRegions: []interface{}{
				map[string]interface{}{
					"type":        "Polygon",
					"coordinates": [][][]float64{{{-5, 35}, {10, 35}, {10, 45}, {-5, 45}, {-5, 35}}}, // Restricted zone
				},
			},
		}

		g, err := NewGeofencer(config)
		if err != nil {
			t.Fatalf("failed to create geofencer: %v", err)
		}

		// Alice can access US items
		aliceItems := []interface{}{
			map[string]interface{}{
				"id": "us-item",
				"geometry": map[string]interface{}{
					"type":        "Point",
					"coordinates": []float64{-100, 40},
				},
			},
			map[string]interface{}{
				"id": "eu-item",
				"geometry": map[string]interface{}{
					"type":        "Point",
					"coordinates": []float64{10, 50},
				},
			},
		}

		alicePrincipal := &auth.Principal{ID: "alice"}
		aliceFiltered := g.FilterResults(aliceItems, alicePrincipal)
		if len(aliceFiltered) != 1 {
			t.Errorf("Alice should see 1 item, got %d", len(aliceFiltered))
		}

		// Bob can access Europe items (excluding denied region)
		bobPrincipal := &auth.Principal{ID: "bob"}
		bobFiltered := g.FilterResults(aliceItems, bobPrincipal)
		if len(bobFiltered) != 1 {
			t.Errorf("Bob should see 1 item, got %d", len(bobFiltered))
		}
	})

	t.Run("role-based access with multiple roles", func(t *testing.T) {
		config := GeofencerConfig{
			RoleRegions: map[string]interface{}{
				"admin": map[string]interface{}{
					"type":        "Polygon",
					"coordinates": [][][]float64{{{-180, -90}, {180, -90}, {180, 90}, {-180, 90}, {-180, -90}}},
				},
				"analyst": map[string]interface{}{
					"type":        "Polygon",
					"coordinates": [][][]float64{{{-50, -50}, {50, -50}, {50, 50}, {-50, 50}, {-50, -50}}},
				},
			},
		}

		g, err := NewGeofencer(config)
		if err != nil {
			t.Fatalf("failed to create geofencer: %v", err)
		}

		adminPrincipal := &auth.Principal{
			ID:    "admin-user",
			Roles: []string{"admin"},
		}

		analystPrincipal := &auth.Principal{
			ID:    "analyst-user",
			Roles: []string{"analyst"},
		}

		adminRegion := g.GetEffectiveRegion(adminPrincipal)
		analystRegion := g.GetEffectiveRegion(analystPrincipal)

		if adminRegion == nil {
			t.Error("admin should have a region")
		}

		if analystRegion == nil {
			t.Error("analyst should have a region")
		}

		// Admin should have global access
		globalReq := &middleware.STACRequest{
			Params: map[string]interface{}{
				"bbox": []float64{-180, -90, 180, 90},
			},
		}

		if err := g.ValidateRequest(context.Background(), globalReq, adminPrincipal); err != nil {
			t.Errorf("admin should be able to access global data: %v", err)
		}

		// Analyst should be restricted
		if err := g.ValidateRequest(context.Background(), globalReq, analystPrincipal); err == nil {
			t.Error("analyst should not be able to access global data")
		}
	})
}

// TestGeofencerWithSpatialIndex was removed alongside the dead
// Geofencer.spatialIndex field (see comment in geofence.go).

// Helper functions

func makeTestItems(count int) []interface{} {
	items := make([]interface{}, count)
	for i := 0; i < count; i++ {
		items[i] = map[string]interface{}{
			"id": "item" + string(rune(i)),
			"geometry": map[string]interface{}{
				"type":        "Point",
				"coordinates": []float64{float64(i), float64(i)},
			},
		}
	}
	return items
}
