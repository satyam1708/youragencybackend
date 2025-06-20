const errorHandler = (err, req, res, next) => {
    console.error("Unhandled Error:", err.stack || err);
    res.status(500).json({ message: "Something went wrong" });
  };
  
  module.exports = errorHandler;
  