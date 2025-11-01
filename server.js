const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const cors = require('cors');
const path = require('path');
const fs = require("fs");
const jwt = require('jsonwebtoken'); // For stateless auth
const rateLimit = require('express-rate-limit');
require("dotenv").config();

// --- Import Models ---
const Agencies = require('../models/Agencies');
const Vehicle = require('../models/Vehicles');
const User = require("../models/User");
const OTP = require("../models/OTP");
const Counter = require("../models/Counter");
const Booking = require("../models/Booking");
const Driver = require("../models/Driver");

const app = express();
app.use(cors());

// ====== Middleware ======
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// FIX: Use process.cwd() to correctly find the 'public' folder from the root
app.use(express.static(path.join(process.cwd(), 'public')));

// ====== MongoDB Setup ======
// FIX: Removed deprecated 'useNewUrlParser' and 'useUnifiedTopology'
mongoose
  .connect(process.env.MONGO_URI, {}) // No options needed
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Error:", err));

// ====== Booking ID Helper ======
// FIX: Added try...catch block to handle database errors
async function getNextBookingId() {
  try {
    const counter = await Counter.findOneAndUpdate(
      { id: "booking_seq" },
      { $inc: { seq: 1 } },
      { new: true, upsert: true }
    );
    if (!counter) {
      throw new Error("Counter not found or created.");
    }
    return "BO113" + counter.seq;
  } catch (error) {
    console.error("Error in getNextBookingId:", error);
    // Re-throw the error to be caught by the API route
    throw new Error("Failed to generate booking ID.");
  }
}

// ====== Email Transporter ======
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.USER,
    pass: process.env.PASS,
  },
});

// Verify transporter on startup
transporter.verify((error, success) => {
  if (error) console.log('❌ Email transporter verification failed:', error);
  else console.log('✅ Email server is ready to send messages');
});

// ====== JWT Authentication Middleware ======
// This replaces sessions for Vercel
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN"

  if (token == null) {
    return res.status(401).json({ success: false, message: "Not logged in" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error("JWT Verify Error:", err.message);
      return res.status(403).json({ success: false, message: "Invalid token" });
    }
    req.user = user;
    next();
  });
}


// ====== OTP Rate Limiter ======
const otpLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  message: { success: false, message: 'Too many OTP requests. Try again after an hour.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ====== Generate OTP ======
app.post('/generate-otp', otpLimiter, async (req, res) => {
  const { email } = req.body;

  try {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.create({ email, otp, createdAt: new Date() });

    const mailOptions = {
      from: process.env.FROM_EMAIL || 'no-reply@sharingyatra.com',
      to: email,
      subject: "🚗 Here's Your Sharing Yatra Access Code",
      html: `
    <div style="font-family: 'Arial', sans-serif; max-width: 550px; margin: auto; background: #ffffff; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.07);">
      
      <div style="background: #2b7dacff; padding: 20px; border-radius: 8px 8px 0 0; text-align: center;">
        <h1 style="color: #ffffff; margin: 0; font-size: 24px; font-weight: 700;">Sharing Yatra</h1>
      </div>
      
      <div style="padding: 30px 35px;">
        <h2 style="color: #333; font-size: 20px; margin-top: 0;">Confirm Your Account</h2>
        <p style="color: #555; font-size: 16px; line-height: 1.6;">
          Thanks for signing up! Please use the following code to complete your registration.
        </p>
        
        <div style="text-align: center; margin: 30px 0;">
          <p style="font-size: 14px; color: #888; margin: 0 0 10px 0;">Your verification code is:</p>
          <div style="background: #f1f8f7; border: 2px dashed #2a9d8f; border-radius: 5px; padding: 15px 20px; display: inline-block;">
            <span style="font-size: 36px; font-weight: 700; color: #264653; letter-spacing: 4px;">${otp}</span>
          </div>
        </div>
        
        <p style="font-size: 15px; color: #e76f51; font-weight: bold; text-align: center;">
          This code is valid for 5 minutes.
        </p>
        <p style="font-size: 14px; color: #555; line-height: 1.6; text-align: center;">
          For your security, please do not share this code with anyone.
        </p>
      </div>
      
      <div style="background: #f9f9f9; padding: 20px 35px; border-radius: 0 0 8px 8px; border-top: 1px solid #eee;">
        <p style="font-size: 12px; color: #999; text-align: center; margin: 0;">
          Happy travels,<br>The Sharing Yatra Team
        </p>
        <p style="font-size: 10px; color: #aaa; text-align: center; margin-top: 10px;">
          © ${new Date().getFullYear()} Sharing Yatra. All rights reserved.
        </p>
      </div>
    </div>
  `
    };

    // Use the global transporter
    await transporter.sendMail(mailOptions);
    
    console.log('✅ OTP email sent to:', email);
    return res.json({ success: true, message: 'OTP sent successfully' });

  } catch (err) {
    console.error('❌ Error generating OTP or sending email:', err);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


// ====== Register (Validate OTP + Save User) ======
app.post('/register', async (req, res) => {
  const { email, username, password, otp, phone, age } = req.body;

  try {
    const otpRecord = await OTP.findOne({ email });
    if (!otpRecord) {
      return res.status(400).json({ success: false, message: 'OTP not generated or expired' });
    }

    if (otpRecord.otp !== otp) {
      return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }

    const otpAge = (Date.now() - otpRecord.createdAt.getTime()) / 1000 / 60;
    if (otpAge > 3) { // 3 minute expiry
      await OTP.deleteOne({ email });
      return res.status(400).json({ success: false, message: 'OTP expired. Please request a new one.' });
    }
    
    // --- All other validations ---
    if (!username || username.trim() === "") {
      return res.status(400).json({ success: false, message: 'Name is required' });
    }
    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 8 characters long, include uppercase, lowercase, number, and a special character."
      });
    }
    const phoneRegex = /^[0-9]{10}$/;
    if (!phoneRegex.test(phone)) {
      return res.status(400).json({ success: false, message: 'Phone number must be 10 digits' });
    }
    if (!age || age.toString().trim() === "") {
      return res.status(400).json({ success: false, message: 'Age is required' });
    }
    // --- End validations ---

    // Saving plain text password as requested
    const newUser = new User({ email, username, password, phone, age });
    await newUser.save();
    await OTP.deleteOne({ email });

    res.json({ success: true, message: 'User registered successfully' });
  } catch (err) {
    console.error('❌ Error registering user:', err.message || err);
    // Check for duplicate key error
    if (err.code === 11000) {
      return res.status(400).json({ success: false, message: 'Email or phone number already exists.' });
    }
    res.status(500).json({ success: false, message: 'Registration failed', error: err.message });
  }
});


// ====== Login Route ======
// FIX: Changed to return a JWT instead of setting a session
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    let account = await User.findOne({ email });
    let userType = "customer";

    if (!account) {
      account = await Agencies.findOne({ email });
      userType = "agency";
    }

    if (!account) {
      return res.status(400).json({ success: false, message: "Account not found" });
    }

    // Using plain text password comparison as requested
    if (account.password !== password) {
      return res.status(400).json({ success: false, message: "Invalid password" });
    }

    // --- JWT CREATION ---
    const userPayload = {
      id: account._id,
      email: account.email,
      phone: account.phone,
      name: userType === "customer" ? account.username : (account.agencyName || "Agency"),
      type: userType
    };
    
    // Make sure JWT_SECRET is in your .env file!
    const token = jwt.sign(
      userPayload,
      process.env.JWT_SECRET,
      { expiresIn: '3h' } // Token expires in 3 hours
    );

    res.json({ success: true, message: "Login successful", token: token });

  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// FIX: This route is now protected by our 'verifyToken' middleware
app.get("/api/profile", verifyToken, (req, res) => {
  // The user data is now in 'req.user' (from the token)
  res.json(req.user);
});

// --- START: RAIL GRAPH IMPLEMENTATION ---
// FIX: Use process.cwd() to correctly find the JSON file
const mumbaiNetwork = JSON.parse(
  fs.readFileSync(path.join(process.cwd(), "public", "stationdata.json"), "utf-8")
);

// Graph API Class (Copied from your graph logic)
class RailGraph {
  /**
  * transferPenalty: cost to transfer between lines at the same station (default 0.5)
  * defaultEdgeWeight: weight used when distance info missing between adjacent stations (default 1)
  */
  constructor({ transferPenalty = 0.5, defaultEdgeWeight = 1 } = {}) {
    this.transferPenalty = transferPenalty;
    this.defaultEdgeWeight = defaultEdgeWeight;
    this.adj = new Map();
    this.nodeInfo = new Map();
    this.stationLines = new Map();
  }
  static nodeId(stationName, lineName) {
    return `${stationName}@@${lineName}`;
  }
  _ensureNode(nodeId, info) {
    if (!this.adj.has(nodeId)) {
      this.adj.set(nodeId, []);
      this.nodeInfo.set(nodeId, info);
      const { stationName, lineName } = info;
      if (!this.stationLines.has(stationName)) this.stationLines.set(stationName, new Set());
      this.stationLines.get(stationName).add(lineName);
    }
  }
  _addEdge(a, b, w, meta = {}) {
    if (!this.adj.has(a) || !this.adj.has(b)) return;
    this.adj.get(a).push({ to: b, weight: w, meta });
    this.adj.get(b).push({ to: a, weight: w, meta });
  }
  buildFromNetwork(network) {
    const stationDistanceLookup = new Map();
    for (const line of network.lines) {
      for (const route of line.routes) {
        for (const st of route.stations) {
          const name = st.station_name;
          if (st.distance_km !== null && st.distance_km !== undefined) {
            if (!stationDistanceLookup.has(name)) stationDistanceLookup.set(name, st.distance_km);
          }
        }
      }
    }
    for (const line of network.lines) {
      const lineName = line.line_name;
      for (const route of line.routes) {
        const stations = route.stations || [];
        for (let i = 0; i < stations.length; i++) {
          const s = stations[i];
          const name = s.station_name;
          const dist = (s.distance_km !== null && s.distance_km !== undefined)
            ? s.distance_km
            : (stationDistanceLookup.has(name) ? stationDistanceLookup.get(name) : null);
          const id = RailGraph.nodeId(name, lineName);
          this._ensureNode(id, { stationName: name, lineName, distance: dist });
        }
        for (let i = 0; i < stations.length - 1; i++) {
          const s1 = stations[i], s2 = stations[i + 1];
          const id1 = RailGraph.nodeId(s1.station_name, lineName);
          const id2 = RailGraph.nodeId(s2.station_name, lineName);
          const d1 = this.nodeInfo.get(id1)?.distance;
          const d2 = this.nodeInfo.get(id2)?.distance;
          let weight;
          if (typeof d1 === 'number' && typeof d2 === 'number') {
            weight = Math.abs(d2 - d1);
            if (weight === 0) weight = 0.0001;
          } else {
            weight = this.defaultEdgeWeight;
          }
          this._addEdge(id1, id2, weight, { type: 'track', routeName: route.route_name, lineName });
        }
      }
    }
    for (const [stationName, lineSet] of this.stationLines.entries()) {
      const lines = Array.from(lineSet);
      if (lines.length <= 1) continue;
      for (let i = 0; i < lines.length; i++) {
        for (let j = i + 1; j < lines.length; j++) {
          const a = RailGraph.nodeId(stationName, lines[i]);
          const b = RailGraph.nodeId(stationName, lines[j]);
          this._addEdge(a, b, this.transferPenalty, { type: 'transfer', stationName });
        }
      }
    }
  }
  findNodesForStation(stationName) {
    const nodes = [];
    for (const [nodeId, info] of this.nodeInfo.entries()) {
      if (info.stationName === stationName) nodes.push(nodeId);
    }
    return nodes;
  }
  shortestPath(startStationName, endStationName) {
    const startNodes = this.findNodesForStation(startStationName);
    const endNodes = new Set(this.findNodesForStation(endStationName));
    if (startNodes.length === 0) return { found: false };
    if (endNodes.size === 0) return { found: false };
    const distances = new Map();
    const prev = new Map();
    const visited = new Set();
    for (const nodeId of this.adj.keys()) {
      distances.set(nodeId, Infinity);
      prev.set(nodeId, null);
    }
    for (const s of startNodes) distances.set(s, 0);
    while (true) {
      let u = null;
      let bestDist = Infinity;
      for (const [nodeId, dist] of distances.entries()) {
        if (!visited.has(nodeId) && dist < bestDist) {
          bestDist = dist;
          u = nodeId;
        }
      }
      if (u === null) break;
      visited.add(u);
      for (const edge of this.adj.get(u)) {
        const v = edge.to;
        if (visited.has(v)) continue;
        const alt = distances.get(u) + edge.weight;
        if (alt < distances.get(v)) {
          distances.set(v, alt);
          prev.set(v, u);
        }
      }
    }
    let bestEnd = null;
    let bestDistance = Infinity;
    for (const e of endNodes) {
      const d = distances.get(e);
      if (typeof d === 'number' && d < bestDistance) {
        bestDistance = d;
        bestEnd = e;
      }
    }
    if (bestEnd === null) return { found: false };
    const nodePath = [];
    let cur = bestEnd;
    while (cur) {
      nodePath.push(cur);
      cur = prev.get(cur);
    }
    nodePath.reverse();
    const path = nodePath.map(nodeId => {
      const info = this.nodeInfo.get(nodeId);
      return { stationName: info.stationName, lineName: info.lineName };
    });
    return {
      found: true,
      totalWeightedDistance: bestDistance,
      path
    };
  }
}

const railGraph = new RailGraph({ transferPenalty: 0.5 });
railGraph.buildFromNetwork(mumbaiNetwork);
console.log("✅ Rail Graph Built (Transfer Penalty: 0.5 km)");
// --- END: RAIL GRAPH IMPLEMENTATION ---

// --- Helper Functions (Unchanged) ---
function parseTime(date, timeString) {
  if (!timeString || !/^\d{1,2}:\d{2}$/.test(timeString)) {
    throw new Error(`Invalid 24-hour time format. Expected "HH:mm", but got "${timeString}"`);
  }
  const [hours, minutes] = timeString.split(":").map(Number);
  const d = new Date(date);
  d.setHours(hours, minutes, 0, 0);
  return d;
}

function formatTime(date) {
  let hours = String(date.getHours()).padStart(2, '0');
  let minutes = String(date.getMinutes()).padStart(2, '0');
  return hours + ':' + minutes;
}

function calculateArrivalTimes(path, startTime, travelDate) {
  const journeyStart = parseTime(travelDate, startTime);
  const stationsInPath = [];
  let currentTime = journeyStart;
  let totalPhysicalDistance = 0;
  for (let i = 0; i < path.length; i++) {
    const { stationName, lineName } = path[i];
    let prevStation = i > 0 ? path[i - 1].stationName : null;
    let prevLine = i > 0 ? path[i - 1].lineName : null;
    if (i > 0) {
      const prevNodeId = RailGraph.nodeId(prevStation, prevLine);
      const currNodeId = RailGraph.nodeId(stationName, lineName);
      const edge = railGraph.adj.get(prevNodeId)?.find(e => e.to === currNodeId);
      if (edge) {
        if (edge.meta.type === 'track') {
          const distanceKm = edge.weight;
          const travelMinutes = distanceKm * 5; // 5 minutes per km
          currentTime = new Date(currentTime.getTime() + travelMinutes * 60000);
          totalPhysicalDistance += distanceKm;
        } else if (edge.meta.type === 'transfer') {
          currentTime = new Date(currentTime.getTime() + 5 * 60000); // 5 min transfer
        }
      }
    }
    if (i === 0 || stationName !== stationsInPath[stationsInPath.length - 1].name) {
      stationsInPath.push({
        name: stationName,
        time: formatTime(currentTime),
        line: lineName
      });
    } else if (stationName === stationsInPath[stationsInPath.length - 1].name) {
      stationsInPath[stationsInPath.length - 1].time = formatTime(currentTime);
      stationsInPath[stationsInPath.length - 1].line = lineName;
    }
  }
  return {
    stations: stationsInPath,
    totalPhysicalDistance
  };
}
// --- End Helper Functions ---


// ====== Shortest Distance API ======
app.get("/api/distance", (req, res) => {
  const { from, to } = req.query;
  if (!from || !to) {
    return res.status(400).json({ success: false, message: "Both 'from' and 'to' stations are required." });
  }
  try {
    const result = railGraph.shortestPath(from, to);
    if (!result.found) {
      return res.status(404).json({ success: false, message: "Route not found between these stations." });
    }
    let totalPhysicalDistance = 0;
    let transfers = 0;
    for (let i = 0; i < result.path.length - 1; i++) {
      const prevNodeId = RailGraph.nodeId(result.path[i].stationName, result.path[i].lineName);
      const currNodeId = RailGraph.nodeId(result.path[i + 1].stationName, result.path[i + 1].lineName);
      const edge = railGraph.adj.get(prevNodeId)?.find(e => e.to === currNodeId);
      if (edge) {
        if (edge.meta.type === 'track') {
          totalPhysicalDistance += edge.weight;
        } else if (edge.meta.type === 'transfer') {
          transfers += 1;
        }
      }
    }
    res.json({
      success: true,
      totalDistance: parseFloat(totalPhysicalDistance.toFixed(2)),
      weightedDistance: parseFloat(result.totalWeightedDistance.toFixed(2)),
      transfers: transfers,
      route: result.path.map(p => p.stationName)
    });
  } catch (error) {
    console.error("Distance API Error:", error);
    res.status(500).json({ success: false, message: "Server error calculating distance." });
  }
});

// ====== Search Rides API ======
app.get("/api/search-rides", async (req, res) => {
  try {
    const { address } = req.query;
    const searchStation = address ? address.toLowerCase() : "";
    console.log("Searching agencies near:", searchStation);

    const agencies = await Agencies.find({
      $expr: {
        $regexMatch: {
          input: searchStation,
          regex: { $concat: ["\\b", "$oprateStation", "\\b"] },
          options: "i"
        }
      }
    });

    if (!agencies.length) {
      return res.status(404).json({ message: "No agencies found for this station." });
    }
    const agenciesWithVehicles = await Promise.all(
      agencies.map(async (agency) => {
        const vehicles = await Vehicle.aggregate([
          {
            $match: { agencyId: agency._id }
          },
          {
            $addFields: {
              converted_capacity: {
                $cond: {
                  if: { $isNumber: "$max_capacity" },
                  then: "$max_capacity",
                  else: { $toInt: "$max_capacity" }
                }
              }
            }
          },
          {
            $match: { converted_capacity: { $gt: 0 } }
          }
        ]);
        return {
          _id: agency._id,
          name: agency.agencyName,
          address: agency.oprateStation,
          vehicles: vehicles
        };
      })
    );
    const agenciesWithAvailableVehicles = agenciesWithVehicles.filter(agency => agency.vehicles.length > 0);
    if (!agenciesWithAvailableVehicles.length) {
      return res.status(404).json({ message: "No agencies found with available vehicles for this station." });
    }
    res.json(agenciesWithAvailableVehicles);
  } catch (err) {
    console.error("Search rides error:", err);
    res.status(500).json({ message: "Server error" });
  }
});


// ====== Matched Saved Rides API ======
app.get("/api/matched-saved-rides", async (req, res) => {
  try {
    const { from, to, date, time } = req.query;
    if (!from || !to || !date || !time) {
      return res.status(400).json({
        success: false,
        message: "'from', 'to', 'date', and 'time' queries are required."
      });
    }

    const fromRegex = new RegExp(`^${from.trim()}$`, "i");
    const toRegex = new RegExp(`^${to.trim()}$`, "i");

    let userDesiredDeparture;
    try {
      userDesiredDeparture = parseTime(date, time);
    } catch (e) {
      return res.status(400).json({ success: false, message: e.message });
    }

    const bufferTimeMs = 20 * 60 * 1000;
    const earliestAcceptableTime = new Date(userDesiredDeparture.getTime() - bufferTimeMs);

    const matchedCandidates = await Booking.find({
      bookingType: "schedule_and_save",
      status: "approved",
      date: date,
      "stations.name": { $all: [fromRegex, toRegex] }
    }).sort({ time: 1 }).limit(50);

    if (!matchedCandidates.length) {
      return res.json({ success: true, rides: [] });
    }

    const fromStationLower = from.trim().toLowerCase();
    const toStationLower = to.trim().toLowerCase();

    const validMatches = matchedCandidates.filter(booking => {
      try {
        let fromIndex = -1;
        let toIndex = -1;
        for (let i = 0; i < booking.stations.length; i++) {
          const stationNameLower = booking.stations[i].name.toLowerCase();
          if (stationNameLower === fromStationLower) {
            fromIndex = i;
          }
          if (stationNameLower === toStationLower) {
            toIndex = i;
          }
        }
        if (fromIndex === -1 || toIndex === -1 || fromIndex >= toIndex) {
          return false;
        }
        const rideDepartureAtFrom = parseTime(booking.date, booking.stations[fromIndex].time);
        return rideDepartureAtFrom >= earliestAcceptableTime;
      } catch (e) {
        console.warn(`Error filtering booking ${booking.bookingId}:`, e.message);
        return false;
      }
    });

    const results = await Promise.all(validMatches.map(async (b) => {
      let agency = null;
      let vehicle = null;
      try { agency = b.agencyId ? await Agencies.findById(b.agencyId).select("agencyName oprateStation email phone") : null; } catch (e) { }
      try { vehicle = b.vehicleId ? await Vehicle.findById(b.vehicleId).select("vehicle_name vehicle_type model rate_per_km max_capacity") : null; } catch (e) { }
      return {
        bookingId: b.bookingId,
        parentBookingId: b._id,
        from: b.from,
        to: b.to,
        date: b.date,
        time: b.time,
        stations: b.stations,
        agency: agency ? { id: agency._id, name: agency.agencyName, address: agency.oprateStation, phone: agency.phone } : null,
        vehicle: vehicle,
        postedBy: b.customerName || b.customerEmail || null,
        status: b.status,
        driverID: b.driverID || null,
        driverName: b.driverName || null
      };
    }));
    res.json({ success: true, rides: results });
  } catch (err) {
    console.error("Error fetching matched saved rides:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ====== Join a saved ride ======
// FIX: Protected with 'verifyToken' and uses 'req.user'
app.post("/api/join-saved-ride", verifyToken, async (req, res) => {
  try {
    // User details now come from req.user
    const { name, email, phone } = req.user;

    const { parentBookingId, pickupAddress, area, city, userFrom, userTo, userDistance, calculatedFare } = req.body;
    if (!parentBookingId || !pickupAddress) return res.status(400).json({ success: false, message: "Missing required fields" });

    const parent = await Booking.findById(parentBookingId);
    if (!parent) return res.status(404).json({ success: false, message: "Parent saved ride not found" });

    const bookingId = await getNextBookingId(); // This will throw if it fails

    const newBooking = new Booking({
      bookingId,
      parentBookingId: parent._id,
      from: userFrom || parent.from,
      to: userTo || parent.to,
      pickupAddress,
      bookingType: "join_request",
      date: parent.date,
      time: formatTime(new Date()),
      area: area || "",
      city: city || "",
      customerName: name, // From token
      customerEmail: email, // From token
      mobile: phone, // From token
      stations: parent.stations,
      totalDistance: parseFloat(userDistance) || parent.totalDistance,
      agencyId: parent.agencyId,
      vehicleId: parent.vehicleId,
      driverID: parent.driverID,
      driverName: parent.driverName,
      fare: parseFloat(calculatedFare) || 0,
      status: parent.status
    });

    await newBooking.save();

    if (parent.agencyId) {
      try {
        const agency = await Agencies.findById(parent.agencyId);
        if (agency && agency.email) {
          await transporter.sendMail({
            from: 'sharingyatra@gmail.com',
            to: agency.email,
            subject: `New join request for ${parent.bookingId}`,
            text: `User ${name || email} requested to join ride ${parent.bookingId} on ${parent.date} ${parent.time}. BookingId: ${bookingId}`
          });
        }
      } catch (mailErr) {
        console.warn("Could not send join notification email:", mailErr);
      }
    }

    res.status(201).json({ success: true, message: "Join request sent", bookingId: newBooking.bookingId });
  } catch (err) {
    console.error("Join saved ride error:", err);
    res.status(500).json({ success: false, message: err.message || "Server error" });
  }
});

// --- API: Fetch Recent Bookings for Current User ---
// FIX: Protected with 'verifyToken' and uses 'req.user'
app.get("/api/recent-bookings", verifyToken, async (req, res) => {
  try {
    const { email: customerEmail, name: customerName } = req.user;

    const bookings = await Booking.find({ customerEmail })
      .sort({ date: -1, time: -1 })
      .limit(5)
      .lean();

    res.json({ success: true, customerName, bookings });
  } catch (err) {
    console.error("Error fetching bookings:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});


// ====== Booking API ======
// FIX: Protected with 'verifyToken' and uses 'req.user'
app.post("/api/bookings", verifyToken, async (req, res) => {
  try {
    // 1. User is already verified by verifyToken middleware
  
    // 2. Get all data from request body
    let {
      from, to, pickupAddress, bookingType, date, time, area, city,
      agencyId, vehicleId, fare, totalDistance
    } = req.body;

    // 3. Handle Express Connect time
    if (bookingType === 'express_connect') {
      const now = new Date();
      date = date || now.toISOString().split('T')[0];
      time = time || `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
    }

    // 4. Validation
    if (!from || !to || !pickupAddress || !date || !time || !area || !city || !agencyId || !vehicleId) {
      return res.status(400).json({ success: false, message: "Missing required booking details." });
    }

    // 5. RailGraph logic
    const shortestPathResult = railGraph.shortestPath(from, to);
    if (!shortestPathResult.found) {
      return res.status(400).json({ success: false, message: "No route found." });
    }
    const { stations: stationsInPath, totalPhysicalDistance } = calculateArrivalTimes(
      shortestPathResult.path, time, date
    );

    // 6. DRIVER LOGIC
    const vehicle = await Vehicle.findById(vehicleId);
    if (!vehicle) {
      return res.status(404).json({ success: false, message: "Vehicle not found." });
    }
    if (!vehicle.assignedDriver) {
      return res.status(400).json({
        success: false,
        message: "This vehicle has no driver assigned."
      });
    }
    const driver = await Driver.findById(vehicle.assignedDriver);
    if (!driver) {
      return res.status(404).json({
        success: false,
        message: "Assigned driver details not found."
      });
    }

    // 7. Get user details from token
    const customerName = req.user.name;
    const customerEmail = req.user.email;
    const mobile = req.user.phone;
    const bookingId = await getNextBookingId(); // This will throw if it fails

    // 8. Create the new Booking object
    const booking = new Booking({
      bookingId,
      from,
      to,
      pickupAddress,
      bookingType,
      date,
      time: formatTime(new Date()), // Use current time for booking creation
      area,
      city,
      customerName,
      customerEmail,
      mobile,
      stations: stationsInPath,
      totalDistance: parseFloat(totalDistance) || parseFloat(totalPhysicalDistance.toFixed(2)),
      agencyId,
      vehicleId,
      fare: parseFloat(fare) || 0,
      status: "pending",
      driverID: driver._id,
      driverName: driver.fullName
    });

    // 9. Save to database
    await booking.save();

    // 10. Send success response
    res.status(201).json({
      success: true,
      bookingId: booking.bookingId,
      message: "Booking request sent successfully"
    });

  } catch (err) {
    // This will catch errors from getNextBookingId, driver logic, etc.
    console.error("Booking error:", err);
    res.status(500).json({ success: false, message: err.message || "Server error" });
  }
});


// --- Static Routes ---
// FIX: All paths now use process.cwd()
app.get('/', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'public', 'option.html'));
});

app.get('/customerSignup.html', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'public', 'customerSignup.html'));
});

app.get('/agency', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'public', 'agencysignup.html'));
});

app.get('/login.html', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'public', 'login.html'));
});

app.get('/dashboard.html', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'public', 'dashboard.html'));
});


// ====== EXPORT THE APP FOR VERCEL ======
module.exports = app;
