// creating token and saving in cookie
const sendToken = (user, statusCode, res) => {
  const token = user.getJWTToken();

  // options for cookie
  const options = {
    expires: new Date(
      Date.now() + process.env.COOKEIE_EXPIRE * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    domain: "https://anjishop.me",
    path: "/",
    secure: true,
    maxAge: new Date() * 0.001 + 300
  };


  res.status(statusCode).cookie("token", token, options).json({
    success: true,
    user,
    token,
  });
};

module.exports = sendToken;
