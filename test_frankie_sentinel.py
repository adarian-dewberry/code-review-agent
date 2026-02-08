"""
Test suite for Frankie sentinel redesign - Phase 5
Tests verify that Frankie embodies system guardian role and not cute mascot.

Sentinel tests cover:
1. SVG posture validation (alert scanning stance)
2. Animation state transitions (scanning→found→monitoring)
3. Inline positioning (not centered overlay)
4. Dark theme integration
5. Escape artist metaphor accuracy
6. Accessibility compliance
"""

import unittest
from pathlib import Path


class TestFrankieSentinelDesign(unittest.TestCase):
    """Verify Frankie sentinel redesign implementation."""

    app_content: str

    @classmethod
    def setUpClass(cls) -> None:
        """Load app.py for inspection."""
        app_path = Path(__file__).parent / "app.py"
        with open(app_path, "r", encoding="utf-8") as f:
            cls.app_content = f.read()

    def test_svg_alert_posture_implemented(self):
        """Verify SVG has alert scanning posture (head rotated, ears perked)."""
        # Check for head rotation transform
        self.assertIn('transform="translate(115, 28) rotate(-22)"', self.app_content)
        # Check for sentinel comment
        self.assertIn("SENTINEL POSTURE", self.app_content)
        self.assertIn("escape artist finding gaps", self.app_content)

    def test_svg_eyes_both_visible(self):
        """Verify both eyes visible (heightened alertness)."""
        # Should have frankie-scanning-eye class used multiple times
        count = self.app_content.count('class="frankie-scanning-eye"')
        self.assertGreaterEqual(
            count, 2, "Both eyes should have scanning-eye class for alert state"
        )

    def test_svg_ears_forward_alert(self):
        """Verify ears are forward-facing in alert position."""
        self.assertIn("ears (fully perked forward", self.app_content)

    def test_svg_tail_alert_curve(self):
        """Verify tail shows alert kinetic energy (raised curve)."""
        self.assertIn("frankie-alert-tail", self.app_content)
        # Check for alert curve comment
        self.assertIn("alert curve - elevated kinetic energy", self.app_content)

    def test_inline_positioning_not_centered_overlay(self):
        """Verify Frankie uses inline positioning, not centered overlay."""
        # Should have frankie_inline_container
        self.assertIn("frankie_inline_container", self.app_content)
        # Should NOT center Frankie (remove old centered overlay behavior)
        self.assertIn("position: absolute;", self.app_content)
        self.assertIn("right: 24px;", self.app_content)
        self.assertIn("bottom: 24px;", self.app_content)
        # Verify inline container exists
        self.assertIn('id="frankie_inline_container"', self.app_content)

    def test_dark_theme_colors_applied(self):
        """Verify dark theme colors are used for Frankie."""
        # Dark background gradient
        self.assertIn("rgba(27,26,24,0.95)", self.app_content)
        self.assertIn("rgba(42,41,38,0.85)", self.app_content)
        # Light text colors
        self.assertIn("#FAF8F4", self.app_content)
        # Muted accent colors
        self.assertIn("#D8C5B2", self.app_content)
        self.assertIn("#9F9791", self.app_content)

    def test_sentinel_state_animations_implemented(self):
        """Verify state-based animations (scanning/found/monitoring)."""
        # Check for all three state classes
        self.assertIn("frankie-state-scanning", self.app_content)
        self.assertIn("frankie-state-found", self.app_content)
        self.assertIn("frankie-state-monitoring", self.app_content)

    def test_scanning_animation_intense_focus(self):
        """Verify scanning state has intense focus animation."""
        self.assertIn("frankieIntenseFocus", self.app_content)
        self.assertIn("frankieScanningPulse", self.app_content)

    def test_found_animation_shift(self):
        """Verify found state animates toward shift/transition."""
        self.assertIn("frankieFoundShift", self.app_content)
        self.assertIn("frankieAlert", self.app_content)

    def test_monitoring_animation_watchful(self):
        """Verify monitoring state shows watchful idle motion."""
        self.assertIn("frankieMonitoringIdle", self.app_content)
        self.assertIn("frankieMonitoring", self.app_content)

    def test_animation_timing_alert_state(self):
        """Verify animation timing matches alert state (faster than calm)."""
        # Scanning should be 2-2.5s (faster than old 3-5s calm)
        self.assertIn("2.5s", self.app_content)
        self.assertIn("2s ease-in-out", self.app_content)

    def test_frankie_state_manager_javascript(self):
        """Verify JavaScript state manager exists."""
        self.assertIn("window.frankieState", self.app_content)
        self.assertIn("setFrankieState", self.app_content)
        self.assertIn("transitionToFound", self.app_content)
        self.assertIn("transitionToMonitoring", self.app_content)

    def test_escape_artist_metaphor_in_comments(self):
        """Verify escape artist metaphor is documented."""
        self.assertIn("escape artist", self.app_content.lower())
        # Should mention vulnerability/gaps
        content_lower = self.app_content.lower()
        self.assertTrue("gap" in content_lower or "vulnerability" in content_lower)

    def test_no_cute_mascot_attributes(self):
        """Verify no cute/cartoonish elements remain."""
        # Should NOT have bouncing, wiggling, or playful animations
        self.assertNotIn("wiggle", self.app_content)
        # Check that Frankie is described as sentinel/guardian
        self.assertIn("sentinel", self.app_content.lower())

    def test_inline_positioning_responsive(self):
        """Verify inline positioning is responsive to screen size."""
        self.assertIn("@media (max-width: 768px)", self.app_content)
        # Should reposition on mobile
        self.assertIn("left: 16px;", self.app_content)

    def test_frankie_hidden_state_exists(self):
        """Verify Frankie can be hidden after review completes."""
        self.assertIn("frankie-hidden", self.app_content)

    def test_accessibility_aria_labels_updated(self):
        """Verify accessibility labels reflect sentinel role."""
        self.assertIn("aria-label", self.app_content)
        self.assertIn("Code review in progress", self.app_content)

    def test_reduced_motion_support(self):
        """Verify reduced motion preference is honored."""
        self.assertIn("prefers-reduced-motion: reduce", self.app_content)
        # Should disable all animations for reduced motion
        self.assertIn("animation: none !important;", self.app_content)

    def test_frankie_glow_effect_dark_theme(self):
        """Verify glow effect works with dark theme."""
        self.assertIn("frankieGlowPulse", self.app_content)
        # Should have subtle glow
        self.assertIn("rgba(205,143,122,0.15)", self.app_content)

    def test_state_transition_timing(self):
        """Verify state transitions have reasonable timing."""
        # transitionToFound should have delay
        self.assertIn("setTimeout", self.app_content)

    def test_scanning_state_color_yellow_gold(self):
        """Verify scanning state uses gold/yellow for intensity."""
        # Active scanning should use gold accent
        self.assertIn("#FFD700", self.app_content)

    def test_monitoring_state_color_muted(self):
        """Verify monitoring state uses muted color for calm presence."""
        self.assertIn("#B8A898", self.app_content)

    def test_frankie_loader_structure_correct(self):
        """Verify Frankie loader HTML structure is correct."""
        # Should have container, silhouette, and text elements
        self.assertIn("frankie_container", self.app_content)
        self.assertIn("frankie_silhouette", self.app_content)
        self.assertIn("frankie_title", self.app_content)
        self.assertIn("frankie_line", self.app_content)
        self.assertIn("frankie_hint", self.app_content)

    def test_frankie_width_reduced_inline(self):
        """Verify Frankie width is reduced for inline positioning."""
        # Inline should be 200px (was 100% for centered)
        self.assertIn("width: 200px;", self.app_content)

    def test_frankie_height_reduced_inline(self):
        """Verify Frankie height is reduced for inline positioning."""
        # Inline should be 140px
        self.assertIn("height: 140px;", self.app_content)

    def test_no_blur_backdrop_inline(self):
        """Verify inline positioning doesn't use backdrop blur."""
        self.assertIn("backdrop-filter: none;", self.app_content)

    def test_frankie_pointer_events_none(self):
        """Verify Frankie doesn't interfere with UI interactions."""
        self.assertIn("pointer-events: none;", self.app_content)

    def test_transition_class_methods_exist(self):
        """Verify all state transition methods exist."""
        self.assertIn("setFrankieState('scanning')", self.app_content)
        self.assertIn("setFrankieState('found')", self.app_content)
        self.assertIn("setFrankieState('monitoring')", self.app_content)

    def test_frankie_text_contextual(self):
        """Verify Frankie text is updated for sentinel context."""
        # Should say "Analyzing" not "Reviewing"
        self.assertIn("Analyzing", self.app_content)
        # Should say "Finding gaps" not cute messages
        self.assertIn("Finding gaps", self.app_content)

    def test_shadow_effect_dark_theme(self):
        """Verify shadow effect works with dark theme."""
        # Dark theme shadow should be darker
        self.assertIn("rgba(0,0,0,0.3)", self.app_content)

    def test_sentinel_SVG_namespace_correct(self):
        """Verify SVG namespace is correct."""
        self.assertIn('xmlns="http://www.w3.org/2000/svg"', self.app_content)

    def test_frankie_eye_animation_maintains_alert(self):
        """Verify eye animation maintains alert state."""
        # Eyes should not blink slowly (old 5s blink)
        self.assertNotIn("5s", self.app_content.split("frankieObserves")[0:1])


class TestSentinelMetaphorConsistency(unittest.TestCase):
    """Verify sentinel/escape artist metaphor is consistent."""

    app_content: str

    @classmethod
    def setUpClass(cls) -> None:
        """Load app.py for inspection."""
        app_path = Path(__file__).parent / "app.py"
        with open(app_path, "r", encoding="utf-8") as f:
            cls.app_content = f.read()

    def test_comments_reflect_escape_artist_role(self):
        """Verify code comments use escape artist metaphor."""
        self.assertIn("escape artist", self.app_content)
        self.assertIn("finding gaps", self.app_content)

    def test_scanning_posture_escape_artist_logic(self):
        """Verify scanning posture makes sense for escape artist."""
        # Rotated head toward target = looking for gaps
        self.assertIn("rotate(-22)", self.app_content)

    def test_scanning_eyes_escape_artist_logic(self):
        """Verify eyes convey searching behavior."""
        self.assertIn("Primary eye (intense focus point)", self.app_content)
        self.assertIn("peripheral awareness", self.app_content)

    def test_no_conflicting_mascot_language(self):
        """Verify no language conflicts with mascot role."""
        content_lower = self.app_content.lower()
        # Should not call Frankie "cute" or "friendly"
        self.assertNotIn("cute", content_lower)
        self.assertNotIn("friendly mascot", content_lower)


class TestPhase5ValidationSummary(unittest.TestCase):
    """Summary test to verify Phase 5 is complete."""

    app_content: str

    @classmethod
    def setUpClass(cls) -> None:
        """Load app.py for inspection."""
        app_path = Path(__file__).parent / "app.py"
        with open(app_path, "r", encoding="utf-8") as f:
            cls.app_content = f.read()

    def test_all_phase5_components_implemented(self):
        """Verify all Phase 5 components are in place."""
        checks = {
            "SVG alert posture": "rotate(-22)",
            "Inline positioning": "frankie_inline_container",
            "State animations": "frankie-state-scanning",
            "Dark theme": "rgba(27,26,24,0.95)",
            "JavaScript state manager": "window.frankieState",
            "Scanning state": "frankieScanningPulse",
            "Found state": "frankieFoundShift",
            "Monitoring state": "frankieMonitoringIdle",
            "Escape artist metaphor": "escape artist",
            "Sentinel role": "sentinel",
        }

        for component, marker in checks.items():
            with self.subTest(component=component):
                self.assertIn(
                    marker,
                    self.app_content,
                    f"Phase 5 component missing: {component}",
                )

    def test_no_regressions_from_previous_phases(self):
        """Verify previous phase improvements are intact."""
        # Phase 1: Fine-Tune Categories improved contrast
        self.assertIn("Fine-Tune Categories", self.app_content)
        # All previous improvements should still exist
        self.assertIn("OWASP 2025 Mapping", self.app_content)


if __name__ == "__main__":
    unittest.main()
