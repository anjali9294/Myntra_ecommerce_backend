const ErrorHandler = require("../utils/errorHandler");
const catchAsyncErrors = require("./catchAsyncErrors");
const jwt = require("jsonwebtoken");
const User = require("../models/userModels");
const cookieParser = require("cookie-parser");

exports.isAuthenticatedUser = catchAsyncErrors(async (req, res, next) => {
  // const token = req.headers.authorization;
  const token = req.cookies.token;
  // console.log(token);
  // console.log(req);
  if (!token) {
    return next(new ErrorHandler("Please Login To Access This resource", 401));
  }

  const decodedData = jwt.verify(token, process.env.JWT_SECRET);
  // console.log(decodedData.id);
  req.user = await User.findById(decodedData.id);
  next();
});

exports.authorzeRoles = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new ErrorHandler(
          `Role ${req.user.role} is not allowed to access this resource`,
          403
        )
      );
    }
    next();
  };
};
