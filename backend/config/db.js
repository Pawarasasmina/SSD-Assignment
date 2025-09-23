const mongoose = require("mongoose");
require("dotenv").config();

const dburl = process.env.MONGO_URI;

if (!dburl) {
  console.error("MONGO_URI is not defined in environment variables");
  process.exit(1);
}

mongoose.set("strictQuery", true, "userNewUrlParser", true);

const connection = async () => {
  try {
    await mongoose.connect(dburl);
    console.log("MongoDB Connected~");
  } catch (e) {
    console.error(e.message);
    process.exit();
  }
};

module.exports = connection;
