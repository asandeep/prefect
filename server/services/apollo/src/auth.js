import passport from 'passport'

const APOLLO_API_PORT = process.env.APOLLO_API_PORT || '4200'
// Ideally auth callback host should be same as address where apollo is running.
// However, when running apollo as part of docker-compose, the application is
// bound to listen at `0.0.0.0`, which is not a valid host for auth callback. In
// that case, the host should be set to `localhost` to make it work.
const APOLLO_AUTH_CALLBACK_HOST =
  process.env.APOLLO_AUTH_CALLBACK_HOST ||
  process.env.APOLLO_API_BIND_ADDRESS ||
  '0.0.0.0'

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
      callbackURL: `http://${APOLLO_AUTH_CALLBACK_HOST}:${APOLLO_API_PORT}/auth/google/callback`
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
