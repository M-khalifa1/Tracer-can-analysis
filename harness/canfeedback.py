"""
canfeedback.py
==============================================================================
Decode the TRACER 2.0 chassis FEEDBACK frames into physical wheel-speed values.

Why this file exists
--------------------
The reviewers want objective evidence that each attack actually affects the
robot. The robot itself reports its motion on the CAN bus, so we decode those
telemetry frames to a number (mm/s and RPM) that we display next to the live
camera. This is pure observation of telemetry the chassis already broadcasts;
it transmits nothing.

Frame layouts come from the AgileX TRACER manual (Motorola / big-endian byte
order, "Table 3.3" and "Table 3.10"):

  0x221  Movement Control Feedback  (chassis speed, ~50 Hz)
         byte[0:1]  signed int16, big-endian  -> linear  velocity  [mm/s]
         byte[2:3]  signed int16, big-endian  -> angular velocity  [0.001 rad/s]

  0x251  Motor 1 (left)  High-speed Feedback  (~50 Hz)
  0x252  Motor 2 (right) High-speed Feedback  (~50 Hz)
         byte[0:1]  signed int16, big-endian  -> motor rotational speed [RPM]
==============================================================================
"""

# CAN identifiers of the feedback frames we decode (see manual tables).
ID_MOTION_FB = 0x221    # chassis linear/angular velocity feedback
ID_MOTOR_L   = 0x251    # left  motor high-speed feedback (RPM)
ID_MOTOR_R   = 0x252    # right motor high-speed feedback (RPM)


def _s16_be(hi, lo):
    """Combine two bytes (big-endian) into a signed 16-bit integer.

    hi : the most-significant byte (byte[0] in the frame)
    lo : the least-significant byte (byte[1] in the frame)
    Returns a Python int in the range [-32768, 32767].
    """
    v = (hi << 8) | lo          # assemble the raw unsigned 16-bit value
    if v >= 0x8000:             # if the sign bit (bit 15) is set ...
        v -= 0x10000            # ... interpret it as a negative two's-complement number
    return v                    # signed result


def decode_motion_fb(data):
    """Decode a 0x221 chassis feedback payload.

    data : a bytes-like object of at least 4 bytes (the CAN payload).
    Returns a dict with the chassis linear and angular velocities.
    """
    lin = _s16_be(data[0], data[1])             # bytes 0-1 -> linear velocity, mm/s
    ang = _s16_be(data[2], data[3])             # bytes 2-3 -> angular velocity, 0.001 rad/s
    return {"linear_mm_s": lin,                 # forward/back chassis speed
            "angular_mrad_s": ang}              # turn rate in milli-rad/s


def decode_motor_fb(data):
    """Decode a 0x251/0x252 motor feedback payload.

    data : a bytes-like object of at least 2 bytes (the CAN payload).
    Returns the motor rotational speed in RPM (signed).
    """
    return _s16_be(data[0], data[1])            # bytes 0-1 -> motor speed, RPM


class WheelState:
    """Holds the most recent decoded wheel-speed values from the bus.

    A single instance is updated every time a feedback frame arrives, so the
    live display can read the current chassis speed and per-wheel RPM at any
    moment. It also tracks the peak magnitudes seen, which is what we assert on
    after each attack phase ("did the wheels react?").
    """

    def __init__(self):
        self.linear_mm_s = 0        # latest chassis linear velocity   [mm/s]
        self.angular_mrad_s = 0     # latest chassis angular velocity   [0.001 rad/s]
        self.motor_l_rpm = 0        # latest left  motor speed          [RPM]
        self.motor_r_rpm = 0        # latest right motor speed          [RPM]
        self.peak_linear = 0        # peak |linear velocity| this phase [mm/s]
        self.peak_rpm = 0           # peak |motor RPM| this phase       [RPM]

    def update(self, can_id, data):
        """Feed one received CAN frame; update state if it is a feedback frame.

        can_id : the 11-bit arbitration identifier of the frame.
        data   : the frame payload (bytes).
        Returns True if the frame was a recognised feedback frame.
        """
        if can_id == ID_MOTION_FB and len(data) >= 4:      # chassis velocity frame
            fb = decode_motion_fb(data)                    # decode linear + angular
            self.linear_mm_s = fb["linear_mm_s"]           # store latest linear speed
            self.angular_mrad_s = fb["angular_mrad_s"]     # store latest turn rate
            self.peak_linear = max(self.peak_linear,       # track the largest magnitude
                                   abs(self.linear_mm_s))  #   seen during this phase
            return True
        if can_id == ID_MOTOR_L and len(data) >= 2:        # left motor RPM frame
            self.motor_l_rpm = decode_motor_fb(data)       # store latest left RPM
            self.peak_rpm = max(self.peak_rpm, abs(self.motor_l_rpm))
            return True
        if can_id == ID_MOTOR_R and len(data) >= 2:        # right motor RPM frame
            self.motor_r_rpm = decode_motor_fb(data)       # store latest right RPM
            self.peak_rpm = max(self.peak_rpm, abs(self.motor_r_rpm))
            return True
        return False                                       # not a feedback frame

    def reset_peaks(self):
        """Clear the per-phase peak trackers before a new attack phase."""
        self.peak_linear = 0       # forget previous phase's peak linear speed
        self.peak_rpm = 0          # forget previous phase's peak motor RPM

    def line(self):
        """Return a compact one-line human-readable status string."""
        return ("wheels: linear=%+5d mm/s  angular=%+5d mrad/s  "
                "Lmotor=%+5d RPM  Rmotor=%+5d RPM"
                % (self.linear_mm_s, self.angular_mrad_s,
                   self.motor_l_rpm, self.motor_r_rpm))
