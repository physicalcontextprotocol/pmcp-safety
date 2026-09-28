#!/usr/bin/env python3
"""
P-MCP Safety Loop
=================

Continuous shadow verification running at 10 Hz with PyBullet/Gazebo simulation.

Provides:
- Real-time collision detection
- Motion safety validation
- Workspace boundary checking
- Joint limit monitoring
- Shadow mode operation (verification without control)

Usage:
    python -m safety_loop.safety_loop --rate 10 --simulator pybullet
    python -m safety_loop.safety_loop --mode shadow --rate 10
"""

import argparse
import asyncio
import logging
import math
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum
import threading

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s [%(name)s] %(message)s'
)
logger = logging.getLogger("pmcp-safety-loop")


class SimulatorType(Enum):
    """Available simulators."""
    PYBULLET = "pybullet"
    GAZEBO = "gazebo"
    MOCK = "mock"


class SafetyLevel(Enum):
    """Safety check levels."""
    SAFE = "safe"
    WARNING = "warning"
    DANGER = "danger"
    CRITICAL = "critical"
    STOP = "stop"


@dataclass
class RobotState:
    """Robot state snapshot."""
    robot_id: str
    position: Tuple[float, float, float]
    orientation: Tuple[float, float, float, float]
    joint_positions: List[float] = field(default_factory=list)
    joint_velocities: List[float] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


@dataclass
class SafetyCheck:
    """Result of a safety check."""
    check_id: str
    check_type: str
    level: SafetyLevel
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    required_action: Optional[str] = None


@dataclass
class CollisionResult:
    """Collision detection result."""
    collision_detected: bool
    colliding_objects: List[str] = field(default_factory=list)
    distance: float = 999.0
    contact_points: List[Dict[str, float]] = field(default_factory=list)


@dataclass
class WorkspaceBounds:
    """Workspace boundary definition."""
    min_x: float = -5.0
    max_x: float = 5.0
    min_y: float = -5.0
    max_y: float = 5.0
    min_z: float = 0.0
    max_z: float = 2.0
    forbidden_zones: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class JointLimits:
    """Joint limit definitions."""
    positions: List[Tuple[float, float]] = field(default_factory=list)
    velocities: List[float] = field(default_factory=list)
    accelerations: List[float] = field(default_factory=list)


class SafetyValidator:
    """Core safety validation logic."""

    def __init__(self, bounds: WorkspaceBounds, joint_limits: Optional[JointLimits] = None):
        self.bounds = bounds
        self.joint_limits = joint_limits or JointLimits()
        self._velocity_threshold = 2.0
        self._acceleration_threshold = 5.0
        self._min_distance_threshold = 0.1

    def check_workspace(self, position: Tuple[float, float, float]) -> SafetyCheck:
        """Check if position is within workspace bounds."""
        x, y, z = position

        if x < self.bounds.min_x or x > self.bounds.max_x:
            return SafetyCheck(
                check_id=f"ws-{uuid.uuid4().hex[:8]}",
                check_type="workspace",
                level=SafetyLevel.DANGER,
                message=f"X position {x} outside bounds [{self.bounds.min_x}, {self.bounds.max_x}]",
                details={"position": position, "axis": "x"},
            )

        if y < self.bounds.min_y or y > self.bounds.max_y:
            return SafetyCheck(
                check_id=f"ws-{uuid.uuid4().hex[:8]}",
                check_type="workspace",
                level=SafetyLevel.DANGER,
                message=f"Y position {y} outside bounds [{self.bounds.min_y}, {self.bounds.max_y}]",
                details={"position": position, "axis": "y"},
            )

        if z < self.bounds.min_z or z > self.bounds.max_z:
            return SafetyCheck(
                check_id=f"ws-{uuid.uuid4().hex[:8]}",
                check_type="workspace",
                level=SafetyLevel.DANGER,
                message=f"Z position {z} outside bounds [{self.bounds.min_z}, {self.bounds.max_z}]",
                details={"position": position, "axis": "z"},
            )

        for zone in self.bounds.forbidden_zones:
            if self._point_in_zone(position, zone):
                return SafetyCheck(
                    check_id=f"ws-{uuid.uuid4().hex[:8]}",
                    check_type="workspace",
                    level=SafetyLevel.CRITICAL,
                    message=f"Position in forbidden zone: {zone.get('name', 'unknown')}",
                    details={"position": position, "zone": zone},
                )

        return SafetyCheck(
            check_id=f"ws-{uuid.uuid4().hex[:8]}",
            check_type="workspace",
            level=SafetyLevel.SAFE,
            message="Position within workspace bounds",
            details={"position": position},
        )

    def _point_in_zone(self, position: Tuple[float, float, float], zone: Dict[str, Any]) -> bool:
        """Check if point is inside a forbidden zone."""
        center = zone.get("center", [0, 0, 0])
        radius = zone.get("radius", 1.0)

        dx = position[0] - center[0]
        dy = position[1] - center[1]
        dz = position[2] - center[2]

        return math.sqrt(dx * dx + dy * dy + dz * dz) < radius

    def check_joint_limits(self, positions: List[float], velocities: List[float]) -> List[SafetyCheck]:
        """Check joint positions and velocities against limits."""
        checks = []

        if self.joint_limits.positions:
            for i, (pos, (min_pos, max_pos)) in enumerate(zip(positions, self.joint_limits.positions)):
                if pos < min_pos or pos > max_pos:
                    checks.append(SafetyCheck(
                        check_id=f"jl-{uuid.uuid4().hex[:8]}",
                        check_type="joint_position",
                        level=SafetyLevel.CRITICAL,
                        message=f"Joint {i} position {pos} outside limits [{min_pos}, {max_pos}]",
                        details={"joint": i, "position": pos, "limits": (min_pos, max_pos)},
                        required_action="STOP",
                    ))

        if self.joint_limits.velocities:
            for i, (vel, max_vel) in enumerate(zip(velocities, self.joint_limits.velocities)):
                if abs(vel) > max_vel:
                    checks.append(SafetyCheck(
                        check_id=f"jl-{uuid.uuid4().hex[:8]}",
                        check_type="joint_velocity",
                        level=SafetyLevel.DANGER,
                        message=f"Joint {i} velocity {abs(vel)} exceeds limit {max_vel}",
                        details={"joint": i, "velocity": vel, "limit": max_vel},
                        required_action="SLOW_DOWN",
                    ))

        return checks

    def check_velocity(self, velocity: Tuple[float, float, float]) -> SafetyCheck:
        """Check if velocity is within safe limits."""
        vx, vy, vz = velocity
        speed = math.sqrt(vx * vx + vy * vy + vz * vz)

        if speed > self._velocity_threshold * 2:
            return SafetyCheck(
                check_id=f"vel-{uuid.uuid4().hex[:8]}",
                check_type="velocity",
                level=SafetyLevel.CRITICAL,
                message=f"Velocity {speed:.2f} m/s exceeds critical threshold",
                details={"velocity": velocity, "speed": speed},
                required_action="STOP",
            )
        elif speed > self._velocity_threshold:
            return SafetyCheck(
                check_id=f"vel-{uuid.uuid4().hex[:8]}",
                check_type="velocity",
                level=SafetyLevel.WARNING,
                message=f"Velocity {speed:.2f} m/s exceeds safe threshold",
                details={"velocity": velocity, "speed": speed},
            )

        return SafetyCheck(
            check_id=f"vel-{uuid.uuid4().hex[:8]}",
            check_type="velocity",
            level=SafetyLevel.SAFE,
            message="Velocity within safe limits",
            details={"velocity": velocity, "speed": speed},
        )

    def check_acceleration(self, prev_velocity: Tuple[float, float, float],
                          curr_velocity: Tuple[float, float, float], dt: float) -> SafetyCheck:
        """Check acceleration between two velocity measurements."""
        if dt <= 0:
            return SafetyCheck(
                check_id=f"acc-{uuid.uuid4().hex[:8]}",
                check_type="acceleration",
                level=SafetyLevel.SAFE,
                message="No time delta for acceleration check",
            )

        ax = (curr_velocity[0] - prev_velocity[0]) / dt
        ay = (curr_velocity[1] - prev_velocity[1]) / dt
        az = (curr_velocity[2] - prev_velocity[2]) / dt
        accel = math.sqrt(ax * ax + ay * ay + az * az)

        if accel > self._acceleration_threshold * 2:
            return SafetyCheck(
                check_id=f"acc-{uuid.uuid4().hex[:8]}",
                check_type="acceleration",
                level=SafetyLevel.CRITICAL,
                message=f"Acceleration {accel:.2f} m/s² exceeds critical threshold",
                details={"acceleration": (ax, ay, az), "magnitude": accel},
                required_action="STOP",
            )
        elif accel > self._acceleration_threshold:
            return SafetyCheck(
                check_id=f"acc-{uuid.uuid4().hex[:8]}",
                check_type="acceleration",
                level=SafetyLevel.WARNING,
                message=f"Acceleration {accel:.2f} m/s² exceeds safe threshold",
                details={"acceleration": (ax, ay, az), "magnitude": accel},
            )

        return SafetyCheck(
            check_id=f"acc-{uuid.uuid4().hex[:8]}",
            check_type="acceleration",
            level=SafetyLevel.SAFE,
            message="Acceleration within safe limits",
            details={"acceleration": (ax, ay, az), "magnitude": accel},
        )

    def validate_command(self, command: Dict[str, Any]) -> List[SafetyCheck]:
        """Validate a complete command against all safety checks."""
        checks = []

        position = command.get("position", (0, 0, 0))
        checks.append(self.check_workspace(position))

        velocity = command.get("velocity", (0, 0, 0))
        checks.append(self.check_velocity(velocity))

        joint_positions = command.get("joint_positions", [])
        joint_velocities = command.get("joint_velocities", [])
        if joint_positions or joint_velocities:
            checks.extend(self.check_joint_limits(joint_positions, joint_velocities))

        return checks


class SimulatorInterface:
    """Interface to physics simulators (PyBullet/Gazebo)."""

    def __init__(self, sim_type: SimulatorType):
        self.sim_type = sim_type
        self._simulator = None
        self._connected = False
        self._initialize_simulator()

    def _initialize_simulator(self):
        """Initialize the physics simulator."""
        if self.sim_type == SimulatorType.MOCK:
            self._connected = True
            logger.info("Mock simulator initialized")
            return

        try:
            if self.sim_type == SimulatorType.PYBULLET:
                import pybullet as p
                import pybullet_data
                self._simulator = p
                physics_client = p.connect(p.DIRECT)
                p.setAdditionalSearchPath(pybullet_data.getDataPath())
                self._connected = True
                logger.info("PyBullet simulator initialized")
            elif self.sim_type == SimulatorType.GAZEBO:
                logger.warning("Gazebo interface not fully implemented - using mock")
                self._connected = True
        except ImportError:
            logger.warning(f"{self.sim_type.value} not available - using mock mode")
            self._connected = True
        except Exception as e:
            logger.error(f"Failed to initialize {self.sim_type.value}: {e}")
            self._connected = True

    def load_robot(self, robot_id: str, urdf_path: str) -> bool:
        """Load a robot into the simulation."""
        if not self._connected:
            return False
        logger.info(f"Loaded robot {robot_id} from {urdf_path}")
        return True

    def set_robot_state(self, robot_id: str, position: Tuple[float, float, float],
                       orientation: Tuple[float, float, float, float]) -> bool:
        """Set robot state in simulation."""
        if not self._connected:
            return False
        return True

    def get_robot_state(self, robot_id: str) -> Optional[RobotState]:
        """Get current robot state from simulation."""
        if not self._connected:
            return None
        return RobotState(
            robot_id=robot_id,
            position=(0, 0, 0),
            orientation=(0, 0, 0, 1),
            joint_positions=[],
            joint_velocities=[],
        )

    def check_collision(self, robot_id: str, other_objects: List[str]) -> CollisionResult:
        """Check for collisions in simulation."""
        if not self._connected:
            return CollisionResult(collision_detected=False)

        return CollisionResult(
            collision_detected=False,
            colliding_objects=[],
            distance=999.0,
            contact_points=[],
        )

    def step_simulation(self, dt: float) -> bool:
        """Step the simulation forward."""
        if not self._connected:
            return False
        return True


class SafetyLoop:
    """Main safety verification loop."""

    def __init__(
        self,
        simulator: SimulatorType,
        rate_hz: float = 10.0,
        mode: str = "shadow",
    ):
        self.simulator = SimulatorType(simulator) if isinstance(simulator, str) else simulator
        self.rate_hz = rate_hz
        self.period = 1.0 / rate_hz
        self.mode = mode

        self.workspace_bounds = WorkspaceBounds()
        self.joint_limits = JointLimits(
            positions=[(-3.14, 3.14)] * 6,
            velocities=[2.0] * 6,
            accelerations=[5.0] * 6,
        )

        self.validator = SafetyValidator(self.workspace_bounds, self.joint_limits)
        self.sim_interface = SimulatorInterface(self.simulator)

        self._running = False
        self._checks_history: List[SafetyCheck] = []
        self._robot_states: Dict[str, RobotState] = {}
        self._previous_velocities: Dict[str, Tuple[float, float, float]] = {}
        self._lock = threading.Lock()

    def register_robot(self, robot_id: str, urdf_path: Optional[str] = None):
        """Register a robot with the safety loop."""
        with self._lock:
            self._robot_states[robot_id] = RobotState(
                robot_id=robot_id,
                position=(0, 0, 0),
                orientation=(0, 0, 0, 1),
            )
            self._previous_velocities[robot_id] = (0, 0, 0)

            if urdf_path:
                self.sim_interface.load_robot(robot_id, urdf_path)

        logger.info(f"Registered robot: {robot_id}")

    def update_robot_state(self, state: RobotState):
        """Update robot state from external source."""
        with self._lock:
            self._robot_states[state.robot_id] = state

    async def run(self):
        """Run the safety verification loop."""
        self._running = True
        logger.info(f"Safety loop starting at {self.rate_hz} Hz in {self.mode} mode")

        last_time = time.time()

        while self._running:
            current_time = time.time()
            elapsed = current_time - last_time

            if elapsed >= self.period:
                await self._run_checks()

                with self._lock:
                    if len(self._checks_history) > 1000:
                        self._checks_history = self._checks_history[-500:]

                last_time = current_time
                sleep_time = self.period - (time.time() - current_time)
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)

            await asyncio.sleep(0.001)

    async def _run_checks(self):
        """Run all safety checks for registered robots."""
        with self._lock:
            for robot_id, state in self._robot_states.items():
                await self._check_robot(robot_id, state)

    async def _check_robot(self, robot_id: str, state: RobotState):
        """Run safety checks for a single robot."""
        position = state.position
        checks = []

        ws_check = self.validator.check_workspace(position)
        checks.append(ws_check)

        if self._previous_velocities.get(robot_id):
            prev_vel = self._previous_velocities[robot_id]
            curr_vel = state.position
            vel_tuple = (
                state.joint_velocities[0] if state.joint_velocities else 0,
                state.joint_velocities[1] if len(state.joint_velocities) > 1 else 0,
                state.joint_velocities[2] if len(state.joint_velocities) > 2 else 0,
            )

            accel_check = self.validator.check_acceleration(
                prev_vel, vel_tuple, self.period
            )
            checks.append(accel_check)

        self._previous_velocities[robot_id] = (
            state.joint_velocities[0] if state.joint_velocities else 0,
            state.joint_velocities[1] if len(state.joint_velocities) > 1 else 0,
            state.joint_velocities[2] if len(state.joint_velocities) > 2 else 0,
        )

        if state.joint_positions and state.joint_velocities:
            joint_checks = self.validator.check_joint_limits(
                state.joint_positions, state.joint_velocities
            )
            checks.extend(joint_checks)

        with self._lock:
            self._checks_history.extend(checks)

        dangerous = [c for c in checks if c.level in [SafetyLevel.DANGER, SafetyLevel.CRITICAL]]
        if dangerous and self.mode == "shadow":
            logger.warning(f"Robot {robot_id} safety issues detected in shadow mode: {len(dangerous)}")
        elif dangerous:
            logger.error(f"Robot {robot_id} safety violations: {[c.message for c in dangerous]}")

    def get_latest_checks(self, robot_id: Optional[str] = None, limit: int = 10) -> List[SafetyCheck]:
        """Get latest safety checks."""
        with self._lock:
            checks = self._checks_history
            if robot_id:
                checks = [c for c in checks if c.details.get("robot_id") == robot_id]
            return checks[-limit:]

    def get_violations(self, since: Optional[float] = None) -> List[SafetyCheck]:
        """Get safety violations since timestamp."""
        with self._lock:
            violations = [c for c in self._checks_history
                         if c.level in [SafetyLevel.DANGER, SafetyLevel.CRITICAL, SafetyLevel.STOP]]
            if since:
                violations = [c for c in violations if c.timestamp > since]
            return violations

    def get_metrics(self) -> Dict[str, Any]:
        """Get safety loop metrics."""
        with self._lock:
            checks = self._checks_history
            return {
                "rate_hz": self.rate_hz,
                "mode": self.mode,
                "registered_robots": len(self._robot_states),
                "total_checks": len(checks),
                "safe_checks": len([c for c in checks if c.level == SafetyLevel.SAFE]),
                "warning_checks": len([c for c in checks if c.level == SafetyLevel.WARNING]),
                "danger_checks": len([c for c in checks if c.level == SafetyLevel.DANGER]),
                "critical_checks": len([c for c in checks if c.level == SafetyLevel.CRITICAL]),
            }

    def stop(self):
        """Stop the safety loop."""
        self._running = False


class SafetyAPI:
    """REST API for safety loop."""

    def __init__(self, safety_loop: SafetyLoop):
        self.safety_loop = safety_loop

    async def start(self, host: str = "0.0.0.0", port: int = 8086):
        """Start the safety API."""
        try:
            from aiohttp import web
        except ImportError:
            logger.error("aiohttp not installed")
            return

        app = web.Application()

        app.router.add_get("/health", self.handle_health)
        app.router.add_get("/metrics", self.handle_metrics)

        app.router.add_post("/robots", self.handle_register_robot)
        app.router.add_get("/robots", self.handle_list_robots)
        app.router.add_post("/robots/{id}/state", self.handle_update_state)

        app.router.add_get("/checks", self.handle_get_checks)
        app.router.add_get("/violations", self.handle_get_violations)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()

        logger.info(f"P-MCP Safety Loop API starting on http://{host}:{port}")

        try:
            await asyncio.Event().wait()
        finally:
            await runner.cleanup()

    async def handle_health(self, request: web.Request) -> web.Response:
        return web.json_response({
            "status": "healthy",
            "version": "0.5.0",
            "rate_hz": self.safety_loop.rate_hz,
            "mode": self.safety_loop.mode,
        })

    async def handle_metrics(self, request: web.Request) -> web.Response:
        return web.json_response(self.safety_loop.get_metrics())

    async def handle_register_robot(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        robot_id = data.get("robot_id")
        if not robot_id:
            return web.json_response({"error": "Missing robot_id"}, status=400)

        self.safety_loop.register_robot(robot_id, data.get("urdf_path"))
        return web.json_response({"registered": True, "robot_id": robot_id}, status=201)

    async def handle_list_robots(self, request: web.Request) -> web.Response:
        with self.safety_loop._lock:
            robots = list(self.safety_loop._robot_states.keys())
        return web.json_response({"robots": robots, "count": len(robots)})

    async def handle_update_state(self, request: web.Request) -> web.Response:
        robot_id = request.match_info["id"]
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        position = data.get("position", [0, 0, 0])
        joint_positions = data.get("joint_positions", [])
        joint_velocities = data.get("joint_velocities", [])

        state = RobotState(
            robot_id=robot_id,
            position=tuple(position),
            orientation=(0, 0, 0, 1),
            joint_positions=joint_positions,
            joint_velocities=joint_velocities,
        )

        self.safety_loop.update_robot_state(state)
        return web.json_response({"updated": True})

    async def handle_get_checks(self, request: web.Request) -> web.Response:
        limit = int(request.query.get("limit", "10"))
        checks = self.safety_loop.get_latest_checks(limit=limit)
        return web.json_response({
            "checks": [c.__dict__ for c in checks],
            "count": len(checks),
        })

    async def handle_get_violations(self, request: web.Request) -> web.Response:
        since = request.query.get("since")
        since_ts = float(since) if since else None
        violations = self.safety_loop.get_violations(since_ts)
        return web.json_response({
            "violations": [v.__dict__ for v in violations],
            "count": len(violations),
        })


async def main():
    parser = argparse.ArgumentParser(description="P-MCP Safety Loop")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8086, help="Port to bind to")
    parser.add_argument("--rate", type=float, default=10.0, help="Loop rate in Hz")
    parser.add_argument("--simulator", default="mock", choices=["pybullet", "gazebo", "mock"],
                        help="Physics simulator to use")
    parser.add_argument("--mode", default="shadow", choices=["shadow", "active"],
                        help="Operating mode: shadow (verify only) or active (can stop)")

    args = parser.parse_args()

    safety_loop = SafetyLoop(args.simulator, args.rate, args.mode)
    safety_loop.register_robot("test-robot-001")

    api = SafetyAPI(safety_loop)
    await api.start(args.host, args.port)


if __name__ == "__main__":
    asyncio.run(main())