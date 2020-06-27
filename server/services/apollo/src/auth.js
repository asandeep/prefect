import passport from 'passport'

// Google OAuth callback url.
const APOLLO_AUTH_CALLBACK_URL =
  process.env.APOLLO_AUTH_CALLBACK_URL || 'http://localhost:4200'

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET

let authenticationMiddleware = function(req, res, next) {
  const userAgent = req.headers['user-agent']
  // When useragent is not present in request headers, we assume the request
  // was made internally and bypass authentication.
  const backendRequest = !userAgent || userAgent.startsWith('python')

  if (backendRequest || req.user || req.path.startsWith('/auth/google')) {
    return next()
  }

  res.redirect('/auth/google')
}

const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: `${APOLLO_AUTH_CALLBACK_URL}/auth/google/callback`
    },
    function(accessToken, refreshToken, profile, done) {
      return done(null, profile)
    }
  )
)

// Serialize logged-in user's profile to session. As there is no database, we
// store the complete user profile as received from OAuth API, into session.
passport.serializeUser((user, done) => {
  done(null, user)
})

// Deserialize user details from session.
passport.deserializeUser((user, done) => {
  done(null, user)
})

export default authenticationMiddleware
