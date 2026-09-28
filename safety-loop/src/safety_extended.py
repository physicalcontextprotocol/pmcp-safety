#!/usr/bin/env python3
"""
P-MCP Safety Loop - Extended Components
=======================================

Additional safety verification components including:
- Advanced collision detection
- Path validation
- Safety zones
- Emergency stop handling
- Safety metrics

"""

import asyncio
import math
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum
import threading
import queue


class CollisionType(Enum):
    """Types of collisions."""
    ROBOT_ROBOT = "robot_robot"
    ROBOT_OBSTACLE = "robot_obstacle"
    ROBOT_BOUNDARY = "robot_boundary"
    ROBOT_ZONE_VIOLATION = "robot_zone_violation"
    SELF_COLLISION = "self_collision"


class SafetyEventType(Enum):
    """Types of safety events."""
    COLLISION = "collision"
    BOUNDARY_VIOLATION = "boundary_violation"
    VELOCITY_EXCEEDED = "velocity_exceeded"
    ACCELERATION_EXCEEDED = "acceleration_exceeded"
    JOINT_LIMIT_VIOLATION = "joint_limit_violation"
    ZONE_VIOLATION = "zone_violation"
    EMERGENCY_STOP = "emergency_stop"
    PROXIMITY_WARNING = "proximity_warning"


@dataclass
class SafetyEvent:
    """A safety event."""
    event_id: str
    event_type: SafetyEventType
    robot_id: str
    severity: str
    message: str
    details: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    position: Optional[Tuple[float, float, float]] = None
    acknowledged: bool = False
    resolved: bool = False


@dataclass
class CollisionResult:
    """Detailed collision detection result."""
    collision_type: CollisionType
    colliding_object: str
    distance: float
    position: Tuple[float, float, float]
    normal: Tuple[float, float, float]
    depth: float = 0.0
    time_to_collision: Optional[float] = None


@dataclass
class PathValidationResult:
    """Result of path validation."""
    valid: bool
    violations: List[str] = field(default_factory=list)
    checkpoints: List[Tuple[float, float, float]] = field(default_factory=list)
    total_distance: float = 0.0
    estimated_time: float = 0.0


@dataclass
class SafetyZone:
    """A defined safety zone."""
    zone_id: str
    name: str
    zone_type: str
    bounds: Dict[str, float]
    prohibited: bool = False
    max_velocity: Optional[float] = None
    max_robots: Optional[int] = None


@dataclass
class EmergencyStopState:
    """Emergency stop state."""
    triggered: bool = False
    trigger_time: Optional[float] = None
    trigger_robot: Optional[str] = None
    trigger_reason: str = ""
    acknowledged: bool = False
    reset_allowed: bool = False


class AdvancedCollisionDetector:
    """Advanced collision detection with prediction."""

    def __init__(self):
        self.robot_positions: Dict[str, Tuple[float, float, float]] = {}
        self.robot_velocities: Dict[str, Tuple[float, float, float]] = {}
        self.obstacles: Dict[str, Tuple[float, float, float, float, float, float]] = {}

    def update_robot_state(self, robot_id: str, position: Tuple[float, float, float],
                         velocity: Tuple[float, float, float]):
        """Update robot state."""
        self.robot_positions[robot_id] = position
        self.robot_velocities[robot_id] = velocity

    def add_obstacle(self, obstacle_id: str, min_pos: Tuple[float, float, float],
                   max_pos: Tuple[float, float, float]):
        """Add an obstacle."""
        self.obstacles[obstacle_id] = min_pos + max_pos

    def predict_collision(self, robot_id: str, time_horizon: float = 1.0) -> Optional[CollisionResult]:
        """Predict potential collision."""
        if robot_id not in self.robot_positions or robot_id not in self.robot_velocities:
            return None

        pos = self.robot_positions[robot_id]
        vel = self.robot_velocities[robot_id]

        speed = math.sqrt(vel[0]**2 + vel[1]**2 + vel[2]**2)
        if speed < 0.01:
            return None

        direction = (vel[0]/speed, vel[1]/speed, vel[2]/speed)

        for obs_id, obs_bounds in self.obstacles.items():
            if self._check_ray_aabb(pos, direction, obs_bounds, time_horizon * speed):
                return CollisionResult(
                    collision_type=CollisionType.ROBOT_OBSTACLE,
                    colliding_object=obs_id,
                    distance=time_horizon * speed,
                    position=pos,
                    normal=direction,
                    time_to_collision=time_horizon,
                )

        return None

    def _check_ray_aabb(self, origin: Tuple[float, float, float], direction: Tuple[float, float, float],
                       bounds: Tuple[float, float, float, float, float, float], max_dist: float) -> bool:
        """Check ray-AABB intersection."""
        (min_x, min_y, min_z, max_x, max_y, max_z) = bounds

        tmin = 0.0
        tmax = max_dist

        for i, (o, d, mn, mx) in enumerate([
            (origin[0], direction[0], min_x, max_x),
            (origin[1], direction[1], min_y, max_y),
            (origin[2], direction[2], min_z, max_z),
        ]):
            if abs(d) < 1e-6:
                if o < mn or o > mx:
                    return False
            else:
                t1 = (mn - o) / d
                t2 = (mx - o) / d

                if t1 > t2:
                    t1, t2 = t2, t1

                tmin = max(tmin, t1)
                tmax = min(tmax, t2)

                if tmin > tmax or tmax < 0:
                    return False

        return True

    def compute_safe_distance(self, robot_id1: str, robot_id2: str) -> float:
        """Compute minimum safe distance between two robots."""
        if robot_id1 not in self.robot_positions or robot_id2 not in self.robot_positions:
            return 999.0

        pos1 = self.robot_positions[robot_id1]
        pos2 = self.robot_positions[robot_id2]

        dx = pos1[0] - pos2[0]
        dy = pos1[1] - pos2[1]
        dz = pos1[2] - pos2[2]
        distance = math.sqrt(dx*dx + dy*dy + dz*dz)

        if robot_id1 in self.robot_velocities and robot_id2 in self.robot_velocities:
            vel1 = self.robot_velocities[robot_id1]
            vel2 = self.robot_velocities[robot_id2]

            rel_vel_x = vel1[0] - vel2[0]
            rel_vel_y = vel1[1] - vel2[1]
            rel_vel_z = vel1[2] - vel2[2]
            rel_speed = math.sqrt(rel_vel_x**2 + rel_vel_y**2 + rel_vel_z**2)

            if rel_speed > 0.01:
                time_to_collision = distance / rel_speed
                if time_to_collision < 2.0:
                    min_distance = 0.3 + time_to_collision * 0.5
                else:
                    min_distance = 0.3
            else:
                min_distance = 0.3
        else:
            min_distance = 0.5

        return min_distance


class PathValidator:
    """Validates paths against safety constraints."""

    def __init__(self):
        self.safety_zones: Dict[str, SafetyZone] = {}
        self.boundary_limits = {
            "min_x": -50.0, "max_x": 50.0,
            "min_y": -50.0, "max_y": 50.0,
            "min_z": 0.0, "max_z": 10.0,
        }

    def add_safety_zone(self, zone: SafetyZone):
        """Add a safety zone."""
        self.safety_zones[zone.zone_id] = zone

    def validate_path(self, path: List[Tuple[float, float, float]],
                     robot_id: str, max_velocity: float) -> PathValidationResult:
        """Validate a path."""
        violations = []
        checkpoints = []

        if not path:
            return PathValidationResult(valid=False, violations=["Empty path"])

        for i, point in enumerate(path):
            if not self._is_within_boundaries(point):
                violations.append(f"Point {i} outside boundaries")

            for zone in self.safety_zones.values():
                if not self._is_within_zone(point, zone):
                    if zone.prohibited:
                        violations.append(f"Point {i} in prohibited zone: {zone.name}")
                    elif zone.max_velocity and max_velocity > zone.max_velocity:
                        violations.append(f"Point {i} exceeds zone max velocity")

            checkpoints.append(point)

        total_distance = self._compute_path_distance(path)
        estimated_time = total_distance / max_velocity if max_velocity > 0 else 0

        return PathValidationResult(
            valid=len(violations) == 0,
            violations=violations,
            checkpoints=checkpoints,
            total_distance=total_distance,
            estimated_time=estimated_time,
        )

    def _is_within_boundaries(self, point: Tuple[float, float, float]) -> bool:
        """Check if point is within boundaries."""
        x, y, z = point
        return (self.boundary_limits["min_x"] <= x <= self.boundary_limits["max_x"] and
                self.boundary_limits["min_y"] <= y <= self.boundary_limits["max_y"] and
                self.boundary_limits["min_z"] <= z <= self.boundary_limits["max_z"])

    def _is_within_zone(self, point: Tuple[float, float, float], zone: SafetyZone) -> bool:
        """Check if point is within zone."""
        bounds = zone.bounds
        x, y, z = point
        return (bounds.get("min_x", -999) <= x <= bounds.get("max_x", 999) and
                bounds.get("min_y", -999) <= y <= bounds.get("max_y", 999) and
                bounds.get("min_z", -999) <= z <= bounds.get("max_z", 999))

    def _compute_path_distance(self, path: List[Tuple[float, float, float]]) -> float:
        """Compute total path distance."""
        if len(path) < 2:
            return 0.0

        total = 0.0
        for i in range(1, len(path)):
            dx = path[i][0] - path[i-1][0]
            dy = path[i][1] - path[i-1][1]
            dz = path[i][2] - path[i-1][2]
            total += math.sqrt(dx*dx + dy*dy + dz*dz)

        return total


class EmergencyStopManager:
    """Manages emergency stop functionality."""

    def __init__(self):
        self.state = EmergencyStopState()
        self.listeners: List[callable] = []
        self.stop_history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def trigger_stop(self, robot_id: str, reason: str):
        """Trigger emergency stop."""
        with self._lock:
            self.state.triggered = True
            self.state.trigger_time = time.time()
            self.state.trigger_robot = robot_id
            self.state.trigger_reason = reason
            self.state.reset_allowed = False

            event = {
                "robot_id": robot_id,
                "reason": reason,
                "timestamp": self.state.trigger_time,
            }
            self.stop_history.append(event)

            for listener in self.listeners:
                try:
                    listener(robot_id, reason)
                except Exception:
                    pass

    def acknowledge_stop(self):
        """Acknowledge the emergency stop."""
        with self._lock:
            self.state.acknowledged = True
            self.state.reset_allowed = True

    def reset_stop(self) -> bool:
        """Reset the emergency stop."""
        with self._lock:
            if self.state.reset_allowed and self.state.acknowledged:
                self.state.triggered = False
                self.state.trigger_time = None
                self.state.trigger_robot = None
                self.state.trigger_reason = ""
                self.state.acknowledged = False
                self.state.reset_allowed = False
                return True
            return False

    def get_state(self) -> EmergencyStopState:
        """Get current emergency stop state."""
        with self._lock:
            return EmergencyStopState(
                triggered=self.state.triggered,
                trigger_time=self.state.trigger_time,
                trigger_robot=self.state.trigger_robot,
                trigger_reason=self.state.trigger_reason,
                acknowledged=self.state.acknowledged,
                reset_allowed=self.state.reset_allowed,
            )

    def register_listener(self, callback: callable):
        """Register a listener for emergency stop events."""
        self.listeners.append(callback)


class SafetyMetricsCollector:
    """Collects safety-related metrics."""

    def __init__(self):
        self.events: List[SafetyEvent] = []
        self.collision_count = 0
        self.violation_count = 0
        self.emergency_stops = 0
        self.total_check_time = 0.0
        self.check_count = 0
        self._lock = threading.Lock()

    def record_event(self, event: SafetyEvent):
        """Record a safety event."""
        with self._lock:
            self.events.append(event)

            if event.event_type == SafetyEventType.COLLISION:
                self.collision_count += 1
            elif event.event_type in [SafetyEventType.BOUNDARY_VIOLATION,
                                      SafetyEventType.VELOCITY_EXCEEDED,
                                      SafetyEventType.ZONE_VIOLATION]:
                self.violation_count += 1
            elif event.event_type == SafetyEventType.EMERGENCY_STOP:
                self.emergency_stops += 1

    def record_check_time(self, check_time: float):
        """Record time for safety check."""
        with self._lock:
            self.total_check_time += check_time
            self.check_count += 1

    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics."""
        with self._lock:
            return {
                "total_events": len(self.events),
                "collision_count": self.collision_count,
                "violation_count": self.violation_count,
                "emergency_stops": self.emergency_stops,
                "avg_check_time_ms": (self.total_check_time / self.check_count * 1000) if self.check_count > 0 else 0,
                "events_by_type": self._count_events_by_type(),
            }

    def _count_events_by_type(self) -> Dict[str, int]:
        """Count events by type."""
        counts = {}
        for event in self.events:
            event_type = event.event_type.value
            counts[event_type] = counts.get(event_type, 0) + 1
        return counts


class SafetyZoneManager:
    """Manages safety zones."""

    def __init__(self):
        self.zones: Dict[str, SafetyZone] = {}
        self._lock = threading.Lock()

    def add_zone(self, zone: SafetyZone):
        """Add a safety zone."""
        with self._lock:
            self.zones[zone.zone_id] = zone

    def remove_zone(self, zone_id: str):
        """Remove a safety zone."""
        with self._lock:
            self.zones.pop(zone_id, None)

    def get_zone(self, zone_id: str) -> Optional[SafetyZone]:
        """Get a zone."""
        with self._lock:
            return self.zones.get(zone_id)

    def check_position(self, position: Tuple[float, float, float],
                     robot_id: str) -> List[str]:
        """Check position against all zones."""
        violations = []

        with self._lock:
            for zone_id, zone in self.zones.items():
                if not self._is_in_zone(position, zone):
                    continue

                if zone.prohibited:
                    violations.append(f"In prohibited zone: {zone.name}")
                if zone.max_robots:
                    current = self._count_robots_in_zone(zone_id, robot_id)
                    if current >= zone.max_robots:
                        violations.append(f"Zone {zone.name} at capacity")

        return violations

    def _is_in_zone(self, position: Tuple[float, float, float], zone: SafetyZone) -> bool:
        """Check if position is in zone."""
        bounds = zone.bounds
        x, y, z = position
        return (bounds.get("min_x", -999) <= x <= bounds.get("max_x", 999) and
                bounds.get("min_y", -999) <= y <= bounds.get("max_y", 999) and
                bounds.get("min_z", -999) <= z <= bounds.get("max_z", 999))

    def _count_robots_in_zone(self, zone_id: str, exclude_robot: str) -> int:
        """Count robots in zone (placeholder)."""
        return 0


class SafetyController:
    """Main safety controller coordinating all safety components."""

    def __init__(self):
        self.collision_detector = AdvancedCollisionDetector()
        self.path_validator = PathValidator()
        self.emergency_stop = EmergencyStopManager()
        self.metrics = SafetyMetricsCollector()
        self.zone_manager = SafetyZoneManager()

        self._running = False
        self._check_interval = 0.1

    async def start(self):
        """Start the safety controller."""
        self._running = True
        while self._running:
            start_time = time.time()

            await self._run_safety_checks()

            check_time = time.time() - start_time
            self.metrics.record_check_time(check_time)

            await asyncio.sleep(self._check_interval)

    async def stop(self):
        """Stop the safety controller."""
        self._running = False

    async def _run_safety_checks(self):
        """Run all safety checks."""
        pass

    def check_position(self, robot_id: str, position: Tuple[float, float, float]) -> List[SafetyEvent]:
        """Check robot position against all safety constraints."""
        events = []

        zone_violations = self.zone_manager.check_position(position, robot_id)
        for violation in zone_violations:
            event = SafetyEvent(
                event_id=f"event-{uuid.uuid4().hex[:8]}",
                event_type=SafetyEventType.ZONE_VIOLATION,
                robot_id=robot_id,
                severity="warning",
                message=violation,
                details={"position": position},
                position=position,
            )
            events.append(event)
            self.metrics.record_event(event)

        return events

    def get_summary(self) -> Dict[str, Any]:
        """Get safety summary."""
        return {
            "metrics": self.metrics.get_metrics(),
            "emergency_stop": self.emergency_stop.get_state().__dict__,
            "zones": len(self.zone_manager.zones),
        }


async def main():
    controller = SafetyController()
    await controller.start()


if __name__ == "__main__":
    asyncio.run(main())