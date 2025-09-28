import express from 'express'
import logger from './middleware/logger.js'
import errorHandler from './middleware/error.js'
import notFound from './middleware/notFound.js'
import connectDB from './db/connectDB.js'
import userRouter from './routes/users.js'
import taskRouter from './routes/tasks.js'
import passport from 'passport'
import initPassportAuthStrategies from './configs/passport.js'
import cors from 'cors'
import helmet from 'helmet'


// create express server and import port number
const server = express()
const SERVER_PORT = process.env.PORT

// connect to DB
connectDB()

// inititalize helmet
server.use( helmet() )

// initialize cors 
server.use( cors() )

// initialize passport for auth
server.use( passport.initialize() )
initPassportAuthStrategies( passport )

// initialize console-logging middleware
server.use( logger )

// initialize json parsing middleware
server.use( express.json() )

// initialize urlencoded parsing middleware
server.use( express.urlencoded({
    extended: false
}))

// server auth routes
server.use( '/auth', userRouter )

// server api routes
server.use( '/api/tasks', taskRouter )

// route-not-found handling middleware
server.use( notFound )

// error middleware
server.use( errorHandler )

// initialize server listen 
server.listen( SERVER_PORT, function( error ) {
    console.log(`Server started on Port: ${ SERVER_PORT }`)
})