  const mongoose = require("mongoose");

  const bookingSchema = new mongoose.Schema({
    bookingId: { type: String, required: true, unique: true },
    customerName: { type: String },
    customerEmail: { type: String },
    mobile: { type: String },
    from: { type: String, required: true },
    to: { type: String, required: true },
    pickupAddress: { type: String, required: true },
    area: { type: String },
    city: { type: String },
    bookingType: { type: String, required: true },
    date: { type: String, required: true },
    time: { type: String, required: true },
    stations: [
      {
        name: { type: String, required: true },
        time: { type: String, required: true }
      }
    ],
    totalDistance: { type: Number, required: true },
    agencyId: {
      type: mongoose.Schema.Types.ObjectId, // This is the correct type for an ID
      ref: 'Agencies', // This links it to your Agencies model
      required: true
    },
    vehicleId: {
      type: mongoose.Schema.Types.ObjectId, // This is the correct type for an ID
      ref: 'Vehicle', // This links it to your Vehicle model
      required: true
    },
    parentBookingId: { 
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Booking',
        required: false
      },
  fare: { type: Number },
    status: { type: String, default: "Pending" }
  });

  module.exports = mongoose.model("Booking", bookingSchema);