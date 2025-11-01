const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require("fs");
const Agencies = require('./models/Agencies');
const Vehicle = require('./models/Vehicles');
const User = require("./models/User");
const OTP = require("./models/OTP");
const Counter = require("./models/Counter");
const Booking = require("./models/Booking");

require("dotenv").config();

const session = require("express-session");
const MongoStore = require("connect-mongo");

const app = express();
app.use(bodyParser.json());
app.use(cors({
  origin: [
    "http://localhost:5000",
    "https://customer-0lnl.onrender.com"
  ],
  methods: "GET,POST",
  credentials: true
}));


app.use(bodyParser.json());

// Serve public folder
app.use(express.static(path.join(__dirname, 'public')));

// ====== MongoDB Setup ======
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Error:", err));

// ====== Booking ID Helper ======
async function getNextBookingId() {
  const counter = await Counter.findOneAndUpdate(
    { id: "booking_seq" },
    { $inc: { seq: 1 } },
    { new: true, upsert: true }
  );
  return "BO113" + counter.seq; // e.g., BO1112
}

// ====== Email Transporter ======
const transporter = nodemailer.createTransport({
  service: 'gmail',
  // auth: {
  //   user: 'sharingyatra@gmail.com',
  //   pass: 'ksnkixrxdktmtbgs' // App password
  // }
  auth: {
    user: process.env.USER,
    pass: process.env.PASS
  }
});

// ====== Session Setup ======
app.use(session({
  secret: process.env.SESSION_SECRET || "secret123",
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI,
    collectionName: "sessions",
  }),
  cookie: {
    maxAge: 1000 * 60 * 60, // 1 hour
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax"
  }
}));

// ====== Generate OTP ======
// ✅ Updated Generate OTP with SendGrid
app.post('/generate-otp', otpLimiter, async (req, res) => {
  const { email } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    await OTP.deleteMany({ email });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.create({ email, otp });

    console.log(`📩 OTP for ${email}: ${otp} (valid 3 min)`);

    // ✅ HTML email template
    const emailHTML = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }
          .container { max-width: 600px; margin: 30px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          .header { text-align: center; color: #5b92e5; margin-bottom: 20px; }
          .otp-box { background: #f0f4f8; padding: 25px; border-radius: 10px; text-align: center; margin: 20px 0; }
          .otp-code { font-size: 36px; font-weight: bold; color: #5b92e5; letter-spacing: 8px; margin: 15px 0; }
          .warning { color: #dc3545; font-weight: bold; margin-top: 20px; }
          .footer { text-align: center; color: #666; font-size: 12px; margin-top: 30px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Sharing Yatra</h1>
            <h2>Email Verification</h2>
          </div>
          <p>Dear user,</p>
          <p>Thank you for signing up with Sharing Yatra. To complete your registration, please use the following One-Time Password (OTP):</p>
          <div class="otp-box">
            <p style="margin: 0; font-size: 14px; color: #666;">Your OTP is:</p>
            <div class="otp-code">${otp}</div>
            <p style="margin: 10px 0 0 0; font-size: 12px; color: #999;">Valid for 3 minutes</p>
          </div>
          <p class="warning">⚠️ Do not share this code with anyone. Our team will never ask for your OTP.</p>
          <p>If you didn't request this OTP, please ignore this email.</p>
          <div class="footer">
            <p>Best regards,<br><strong>Sharing Yatra Team</strong></p>
            <p>This is an automated message, please do not reply.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    // ✅ Send email via SendGrid
    const result = await sendEmailViaSendGrid(
      email,
      'Your OTP Code - Sharing Yatra',
      `Your OTP is ${otp}. It will expire in 3 minutes. Do not share this code with anyone.`,
      emailHTML
    );

    if (result.success) {
      res.json({ success: true, message: 'OTP sent successfully to your email' });
    } else {
      // OTP still saved in DB, but email failed
      res.status(500).json({ 
        success: false, 
        message: 'Failed to send OTP email. Please try again.' 
      });
    }

  } catch (err) {
    console.error('❌ Error in generate-otp:', err);
    res.status(500).json({ success: false, message: 'Failed to send OTP' });
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

    if (!username || username.trim() === "") {
      return res.status(400).json({ success: false, message: 'Name is required' });
    }

    if (otpRecord.otp !== otp) {
      return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }

    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
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

    const newUser = new User({ email, username, password, phone, age });
    await newUser.save();
    await OTP.deleteOne({ email });

    res.json({ success: true, message: 'User registered successfully' });
  } catch (err) {
    console.error('Error registering user:', err);
    res.status(500).json({ success: false, message: 'Registration failed' });
  }
});

// ====== Routes ======
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'option.html'));
});

app.get('/customerSignup.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'customerSignup.html'));
});

app.get('/agency', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'agencysignup.html'));
});

// ====== Login Route ======
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

    if (account.password !== password) {
      return res.status(400).json({ success: false, message: "Invalid password" });
    }

    req.session.user = {
      id: account._id,
      email: account.email,
      phone: account.phone,
      name: userType === "customer" ? account.username : "Agency",
      type: userType
    };
    res.json({ success: true, message: "Login successful" });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/api/profile", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "Not logged in" });
  }
  res.json(req.session.user);
});

app.get("/dashboard", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login.html");
  }
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// --- START: RAIL GRAPH IMPLEMENTATION ---

// Load station data once from JSON file
const mumbaiNetwork = JSON.parse(
  fs.readFileSync(path.join(__dirname, "public", "stationdata.json"), "utf-8")
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

    // adjacency map: nodeId -> [ { to: nodeId, weight, meta } ]
    this.adj = new Map();

    // nodeInfo: nodeId -> { stationName, lineName, distance (may be null) }
    this.nodeInfo = new Map();

    // helper: stationName -> Set(lineName)
    this.stationLines = new Map();
  }

  // node id for a station occurrence on a particular line
  static nodeId(stationName, lineName) {
    return `${stationName}@@${lineName}`;
  }

  _ensureNode(nodeId, info) {
    if (!this.adj.has(nodeId)) {
      this.adj.set(nodeId, []);
      this.nodeInfo.set(nodeId, info);
      // register stationLines
      const { stationName, lineName } = info;
      if (!this.stationLines.has(stationName)) this.stationLines.set(stationName, new Set());
      this.stationLines.get(stationName).add(lineName);
    }
  }

  _addEdge(a, b, w, meta = {}) {
    if (!this.adj.has(a) || !this.adj.has(b)) return; // silently skip if node is missing
    this.adj.get(a).push({ to: b, weight: w, meta });
    this.adj.get(b).push({ to: a, weight: w, meta });
  }

  // Build graph from your network JSON
  buildFromNetwork(network) {
    // first pass: station -> first-known numeric distance (for fallback)
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

    // create nodes for every station occurrence and add edges between adjacent stations on same route
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

        // Add edges between adjacent stations on this route
        for (let i = 0; i < stations.length - 1; i++) {
          const s1 = stations[i], s2 = stations[i + 1];
          const id1 = RailGraph.nodeId(s1.station_name, lineName);
          const id2 = RailGraph.nodeId(s2.station_name, lineName);

          // compute weight using distances when available
          const d1 = this.nodeInfo.get(id1)?.distance;
          const d2 = this.nodeInfo.get(id2)?.distance;
          let weight;
          if (typeof d1 === 'number' && typeof d2 === 'number') {
            weight = Math.abs(d2 - d1);
            // If somehow weight is 0 (same distance), still set to a small positive number
            if (weight === 0) weight = 0.0001;
          } else {
            // fallback
            weight = this.defaultEdgeWeight;
          }

          this._addEdge(id1, id2, weight, { type: 'track', routeName: route.route_name, lineName });
        }
      }
    }

    // Add transfer edges between different line-nodes that represent the same station name
    for (const [stationName, lineSet] of this.stationLines.entries()) {
      const lines = Array.from(lineSet);
      if (lines.length <= 1) continue;
      // fully connect the occurrences with transferPenalty
      for (let i = 0; i < lines.length; i++) {
        for (let j = i + 1; j < lines.length; j++) {
          const a = RailGraph.nodeId(stationName, lines[i]);
          const b = RailGraph.nodeId(stationName, lines[j]);
          // transfer edge
          this._addEdge(a, b, this.transferPenalty, { type: 'transfer', stationName });
        }
      }
    }
  }

  // find all nodeIds for a given stationName
  findNodesForStation(stationName) {
    const nodes = [];
    for (const [nodeId, info] of this.nodeInfo.entries()) {
      if (info.stationName === stationName) nodes.push(nodeId);
    }
    return nodes;
  }

  // Dijkstra over nodeIds. startStationName/endStationName are station names (not nodeIds)
  shortestPath(startStationName, endStationName) {
    const startNodes = this.findNodesForStation(startStationName);
    const endNodes = new Set(this.findNodesForStation(endStationName));
    if (startNodes.length === 0) return { found: false };
    if (endNodes.size === 0) return { found: false };

    // prepare distances and prev
    const distances = new Map();
    const prev = new Map();
    const visited = new Set();
    for (const nodeId of this.adj.keys()) {
      distances.set(nodeId, Infinity);
      prev.set(nodeId, null);
    }
    // initialize start nodes
    for (const s of startNodes) distances.set(s, 0);

    // Priority Queue based Dijkstra for efficiency (though keeping simple selection for now)
    while (true) {
      // pick unvisited node with smallest distance
      let u = null;
      let bestDist = Infinity;
      for (const [nodeId, dist] of distances.entries()) {
        if (!visited.has(nodeId) && dist < bestDist) {
          bestDist = dist;
          u = nodeId;
        }
      }
      if (u === null) break; // all remaining unreachable
      visited.add(u);

      // relax neighbors
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

    // find best end node
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

    // reconstruct path
    const nodePath = [];
    let cur = bestEnd;
    while (cur) {
      nodePath.push(cur);
      cur = prev.get(cur);
    }
    nodePath.reverse();

    // format path as readable sequence (extracting just what's needed for booking)
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

// Global RailGraph instance
const railGraph = new RailGraph({ transferPenalty: 0.5 });
railGraph.buildFromNetwork(mumbaiNetwork);
console.log("✅ Rail Graph Built (Transfer Penalty: 0.5 km)");
// --- END: RAIL GRAPH IMPLEMENTATION ---

// REMOVED: The old stationData definition and unused getRouteDetails function
function parseTime(date, timeString) {
  if (!timeString || !/^\d{1,2}:\d{2}$/.test(timeString)) {
    // Ab yeh sirf "HH:mm" format accept karega
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
  return hours + ':' + minutes; // e.g., "09:05" or "15:08"
}

// NEW FUNCTION: Calculates arrival times based on shortest path
// This replaces the old simple getRouteDetails
function calculateArrivalTimes(path, startTime, travelDate) {
  const journeyStart = parseTime(travelDate, startTime);
  const stationsInPath = []; // Stores the final, simplified path
  let currentTime = journeyStart;
  let totalPhysicalDistance = 0;

  for (let i = 0; i < path.length; i++) {
    const { stationName, lineName } = path[i];

    let prevStation = i > 0 ? path[i - 1].stationName : null;
    let prevLine = i > 0 ? path[i - 1].lineName : null;

    // 1. Calculate time change from the previous step (track or transfer)
    if (i > 0) {
      const prevNodeId = RailGraph.nodeId(prevStation, prevLine);
      const currNodeId = RailGraph.nodeId(stationName, lineName);

      const edge = railGraph.adj.get(prevNodeId)?.find(e => e.to === currNodeId);

      if (edge) {
        if (edge.meta.type === 'track') {
          // Track travel time
          const distanceKm = edge.weight;
          const travelMinutes = distanceKm * 5; // 5 minutes per km
          currentTime = new Date(currentTime.getTime() + travelMinutes * 60000);
          totalPhysicalDistance += distanceKm;
        } else if (edge.meta.type === 'transfer') {
          // Transfer penalty time (assuming 5 minutes fixed time penalty)
          currentTime = new Date(currentTime.getTime() + 5 * 60000);
          // No physical distance added for transfer
        }
      }
    }

    // 2. Check for MERGE/FILTER: If current station is a transfer point (same name as previous, different line)
    // and it was the departure node of the transfer, we don't need a separate entry.

    // If we are at the START station OR if the current station is NOT the same as the last recorded station
    if (i === 0 || stationName !== stationsInPath[stationsInPath.length - 1].name) {
      // This is a new station (or the starting station) - add it to the simplified path
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
    totalPhysicalDistance // Return the actual physical distance
  };
}
// This section must be in your server.js to fix the 404 error

// ====== Shortest Distance API (NEW) ======
app.get("/api/distance", (req, res) => {
  const { from, to } = req.query;

  if (!from || !to) {
    // Return JSON 400 for missing inputs
    return res.status(400).json({ success: false, message: "Both 'from' and 'to' stations are required." });
  }


  try {
    const result = railGraph.shortestPath(from, to);

    if (!result.found) {
      // Return JSON 404 for route not found
      return res.status(404).json({ success: false, message: "Route not found between these stations." });
    }

    // ... (rest of the logic to calculate physical distance/transfers)
    let totalPhysicalDistance = 0;
    let transfers = 0;

    // Iterate through the path to separate physical distance and transfers
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

app.get("/api/search-rides", async (req, res) => {
  try {
    const { address } = req.query;
    const searchStation = address ? address.toLowerCase() : "";
    console.log("Searching agencies near:", searchStation);

    // FIX #1 & #2: Using the correct 'Agencies' model and the correct query logic
    const agencies = await Agencies.find({
      $expr: {
        $regexMatch: {
          input: searchStation, // The full address (e.g., "near station, thane")
          regex: { $concat: ["\\b", "$oprateStation", "\\b"] }, // The station name (e.g., "thane")
          options: "i" // Case-insensitive
        }
      }
    });

    if (!agencies.length) {
      // FIX #3: Send a proper 404 error, not a 200 OK
      return res.status(404).json({ message: "No agencies found for this station." });
    }

    // For each agency, fetch its vehicles
    const agenciesWithVehicles = await Promise.all(
      agencies.map(async (agency) => {
        // FIX #1: Use the correct model variable 'Vehicle' (singular)
        const vehicles = await Vehicle.find({ agencyId: agency._id });

        // This format matches what your frontend expects
        return {
          _id: agency._id,
          name: agency.agencyName,
          address: agency.oprateStation,
          vehicles: vehicles
        };
      })
    );

    console.log("✅ agenciesWithVehicles:", agenciesWithVehicles.length);
    // FIX #3: Send the array directly, not wrapped in an object
    res.json(agenciesWithVehicles);

  } catch (err) {
    console.error("❌ Error while searching rides:", err);
    res.status(500).json({ success: false, message: "Server error while searching rides." });
  }
});

// UPDATED: To find rides based on a 'from' and 'to' segment and time
app.get("/api/matched-saved-rides", async (req, res) => {
  console.log("===== SHARING RIDE SEARCH RECEIVED =====");
  console.log(req.query);
  console.log("======================================");
  try {
    // 1. Get new query parameters from User 2
    const { from, to, date, time } = req.query;
    if (!from || !to || !date || !time) {
      return res.status(400).json({
        success: false,
        message: "'from', 'to', 'date', and 'time' (earliest departure) queries are required."
      });
    }

    // 2. Create case-insensitive regex for DB query
    const fromRegex = new RegExp(`^${from.trim()}$`, "i");
    const toRegex = new RegExp(`^${to.trim()}$`, "i");

    // Parse User 2's desired departure time (using new 24hr parseTime)
    let userDesiredDeparture;
    try {
      userDesiredDeparture = parseTime(date, time);
    } catch (e) {
      return res.status(400).json({ success: false, message: e.message });
    }

    // 3. Initial DB query: Find rides on the same day that contain BOTH stations
    const matchedCandidates = await Booking.find({
      bookingType: "schedule_and_save",
      status: { $nin: ["cancelled", "completed"] },
      date: date, // Filter by the exact date
      "stations.name": { $all: [fromRegex, toRegex] } // Find docs that contain BOTH stations
    }).sort({ time: 1 }).limit(50); // Sort by the ride's main start time

    if (!matchedCandidates.length) {
      return res.json({ success: true, rides: [] }); // No candidates found
    }

    // 4. Post-processing: Filter candidates by station ORDER and TIME
    const fromStationLower = from.trim().toLowerCase();
    const toStationLower = to.trim().toLowerCase();

    const validMatches = matchedCandidates.filter(booking => {
      try {
        let fromIndex = -1;
        let toIndex = -1;

        // Find the indices of User 2's 'from' and 'to' stations
        for (let i = 0; i < booking.stations.length; i++) {
          const stationNameLower = booking.stations[i].name.toLowerCase();
          if (stationNameLower === fromStationLower) {
            fromIndex = i;
          }
          if (stationNameLower === toStationLower) {
            toIndex = i;
          }
        }

        // Check 1: Order must be correct ('from' must come before 'to')
        if (fromIndex === -1 || toIndex === -1 || fromIndex >= toIndex) {
          return false;
        }

        // Check 2: Time must be compatible
        // Get the ride's *actual* departure time from User 2's 'from' station
        // This will now use the new 24hr-only parseTime
        const rideDepartureAtFrom = parseTime(booking.date, booking.stations[fromIndex].time);

        // The ride is valid if its departure from that station is *at or after* User 2's desired time
        return rideDepartureAtFrom >= userDesiredDeparture;

      } catch (e) {
        // This will catch errors if database data is still "AM/PM"
        console.warn(`Error filtering booking ${booking.bookingId} (Check for AM/PM data):`, e.message);
        return false;
      }
    });

    // 5. Enrich the valid results
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
        totalDistance: b.totalDistance,
        fare: b.fare,
        agency: agency ? { id: agency._id, name: agency.agencyName, address: agency.oprateStation, phone: agency.phone } : null,
        vehicle: vehicle,
        postedBy: b.customerName || b.customerEmail || null,
        status: b.status
      };
    }));

    res.json({ success: true, rides: results });
  } catch (err) {
    console.error("Error fetching matched saved rides:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ====== Join a saved ride (create a join request referencing parent saved ride) ======
app.post("/api/join-saved-ride", async (req, res) => {
  try {
    if (!req.session.user) return res.status(401).json({ success: false, message: "Not logged in" });

const { parentBookingId, pickupAddress, area, city, userFrom, userTo, userDistance, calculatedFare } = req.body;
    if (!parentBookingId || !pickupAddress) return res.status(400).json({ success: false, message: "Missing required fields" });

    const parent = await Booking.findById(parentBookingId);
    if (!parent) return res.status(404).json({ success: false, message: "Parent saved ride not found" });

    // create a new booking as a join request. keep reference to parent
    const bookingId = await getNextBookingId();

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
      customerName: req.session.user.name,
      customerEmail: req.session.user.email,
      mobile: req.session.user.phone,
      stations: parent.stations, // copy for visibility
      totalDistance: parseFloat(userDistance) || parent.totalDistance, // Save user's distance, fallback to parent's
      agencyId: parent.agencyId, // <-- Copied from parent
      vehicleId: parent.vehicleId,
      fare: parseFloat(calculatedFare) || 0, // Send the calculated fare
      status: "join_requested"
    });

    await newBooking.save();

    // optionally notify agency or ride owner via email (basic example)
    if (parent.agencyId) {
      try {
        const agency = await Agencies.findById(parent.agencyId);
        if (agency && agency.email) {
          await transporter.sendMail({
            from: 'sharingyatra@gmail.com',
            to: agency.email,
            subject: `New join request for ${parent.bookingId}`,
            text: `User ${req.session.user.name || req.session.user.email} requested to join ride ${parent.bookingId} on ${parent.date} ${parent.time}. BookingId: ${bookingId}`
          });
        }
      } catch (mailErr) {
        console.warn("Could not send join notification email:", mailErr);
      }
    }

    res.status(201).json({ success: true, message: "Join request sent", bookingId: newBooking.bookingId });
  } catch (err) {
    console.error("Join saved ride error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});
// REPLACE your old /api/my-bookings route with this one

// --- API: Fetch Recent Bookings for Current User ---
app.get("/api/recent-bookings", async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(401).json({ success: false, message: "Not logged in" });
    }

    const { email: customerEmail, name: customerName } = req.session.user;

    const bookings = await Booking.find({ customerEmail })
      .sort({ date: -1, time: -1 }) // latest first
      .limit(5)
      .lean();

    res.json({ success: true, customerName, bookings });
  } catch (err) {
    console.error("Error fetching bookings:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});


// ====== Booking API ======
app.post("/api/bookings", async (req, res) => {
  try {
    // CORRECTED: The original 'if (!req.session.user)' check was commented out. It's good practice to keep it.
    if (!req.session.user) {
      return res.status(401).json({ message: "Not logged in" });
    }

    let {
      from, to, pickupAddress, bookingType, date, time, area, city,
      agencyId, vehicleId, fare, totalDistance
    } = req.body;

    // --- CRITICAL FIX from your code: Handle Express Connect ---
    if (bookingType === 'express_connect') {
      const now = new Date();
      date = date || now.toISOString().split('T')[0];
      time = time || `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
    }

    if (!from || !to || !pickupAddress || !date || !time || !area || !city || !agencyId || !vehicleId) {
      return res.status(400).json({ success: false, message: "Missing required booking details." });
    }

    // The RailGraph logic for calculating final route details remains
    const shortestPathResult = railGraph.shortestPath(from, to);
    if (!shortestPathResult.found) {
      return res.status(400).json({ success: false, message: "No route found." });
    }
    const { stations: stationsInPath, totalPhysicalDistance } = calculateArrivalTimes(
      shortestPathResult.path, time, date
    );

    const customerName = req.session.user.name;
    const customerEmail = req.session.user.email;
    const mobile = req.session.user.phone;
    const bookingId = await getNextBookingId();

    const booking = new Booking({
      bookingId,
      from,
      to,
      pickupAddress,
      bookingType,
      date,
      time,
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
      status: "pending"
    });

    await booking.save();

    res.status(201).json({
      success: true,
      bookingId: booking.bookingId,
      message: "Booking request sent successfully"
    });
  } catch (err) {
    console.error("Booking error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});