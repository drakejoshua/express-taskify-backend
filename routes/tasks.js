import express from 'express'
import passport from 'passport'
import { param, body, query, validationResult } from 'express-validator'
import { error_def } from '../utils/error_def.js'
import { reportAPIRateLimitError, reportInvalidRequestFilterError, reportInvalidRequestLimitError, reportInvalidRequestOrderError, reportInvalidRequestSortError, reportInvalidRequestTaskIdError, reportInvalidTaskDateError, reportInvalidTaskObjectiveError, reportTaskNotFoundError } from '../utils/errorReporters.js'
import Task from '../db/taskSchema.js'
import { prepareTaskResponse } from '../utils/prepareResponse.js'
import rateLimit, { ipKeyGenerator } from 'express-rate-limit'


const router = express.Router()

// create rate limiter for API endpoints
const apiRateLimiter = rateLimit({
    windowMs: 1000 * 60 * 15,
    max: 10,
    headers: false,
    keyGenerator: function( req, res ) {
        return req.user ? req.user.id : ipKeyGenerator( req, res )
    },
    handler: function( req, res, next, options ) {
        reportAPIRateLimitError( next )
    }
})

router.use( apiRateLimiter )

// GET /api/tasks - get all the tasks created by authenticated user
router.get('/', 
    passport.authenticate('jwt', { session: false } ),
    [
        query("limit")
            .optional()
            .default(10)
            .isInt({ min: 1, max: 100 })
            .withMessage( error_def.INVALID_REQUEST_LIMIT )
            .toInt()
            .bail(),
        query("sort")
            .optional()
            .default("text")
            .toLowerCase()
            .isIn([ "text", "date" ])
            .withMessage( error_def.INVALID_REQUEST_SORT )
            .bail(),
        query("order")
            .optional()
            .toUpperCase()
            .default("DESC")
            .isIn([ "ASC", "DESC" ])
            .withMessage( error_def.INVALID_REQUEST_ORDER )
            .bail(),
        query("filter")
            .optional()
            .isString()
            .withMessage( error_def.INVALID_REQUEST_FILTER )
            .bail()
    ],
    async function( req, res, next ) {
        // get any validation errors
        const errors = validationResult( req )

        // check if any validation errors and report them
        if ( !errors.isEmpty() ) {
            switch( errors.array()[0].msg ) {
                case error_def.INVALID_REQUEST_LIMIT:
                    return reportInvalidRequestLimitError( next )
                
                case error_def.INVALID_REQUEST_SORT:
                    return reportInvalidRequestSortError( next )
                
                case error_def.INVALID_REQUEST_ORDER:
                    return reportInvalidRequestOrderError( next )
                
                case error_def.INVALID_REQUEST_FILTER:
                    return reportInvalidRequestFilterError( next )
            }
        }

        try {
            // extract query information from request
            const limit = req.query.limit
            const sort = req.query.sort
            const order = req.query.order == 'ASC' ? 1 : -1
            const filter = req.query.filter       // represents search term

            // build mongoose find() query
            const query = {
                user_id: req.user._id
            }

            // filter for search term if specified
            if ( filter ) {
                query.text = { $regex: filter, $options: 'i' }
            }

            // get the tasks created by authenticated user using the query info
            const tasksToReturn = await Task.find( query, {
                                        text: 1,
                                        date: 1,
                                        user_id: 1
                                    })
                                    .limit( limit )
                                    .sort( { [ sort ]: order })

            // get the total number of tasks created by authenticated user
            const totalTasks = await Task.countDocuments( query )

            // send success repoonse with retrieved date since no errors
            res.json({
                status: "success",
                data: {
                    tasks: tasksToReturn,
                    totalTasks: totalTasks
                }
            })
        } catch( err ) {
            err.errorCode = error_def.SERVER_ERROR
            return next( err )
        }
    }
)

// GET /api/tasks/:id - get task info as created by authenticated user
router.get('/:id', 
    passport.authenticate( 'jwt', { session: false } ),
    [
        param("id")
            .exists()
            .withMessage( error_def.INVALID_REQUEST_TASK_ID )
            .bail()
            .isMongoId()
            .withMessage( error_def.INVALID_REQUEST_TASK_ID )
            .bail()
    ],
    async function( req, res, next ) {
        // get validation errors from request if any
        const errors = validationResult( req )

        // check if there are any validation errors and report them
        if ( !errors.isEmpty() ) {
            switch( errors.array()[0].msg ) {
                case error_def.INVALID_REQUEST_TASK_ID:
                    return reportInvalidRequestTaskIdError( next )
            }
        }

        try {
            // get id to search for from request
            const idFromRequest = req.params.id

            // get task with search id from database
            const taskWithID = await Task.where("_id")
                                        .equals(idFromRequest)
                                        .select("text date _id")

            // check if task if valid and return success response,
            // if not, report error
            if ( taskWithID ) {
                res.json( taskWithID )
            } else {
                return reportTaskNotFoundError( next )
            }
        } catch( err ) {
            err.errorCode = error_def.SERVER_ERROR
            return next( err )
        }
    }
)

// POST /api/tasks - create a new task for authenticated user
router.post("/",
    passport.authenticate( 'jwt', { session: false } ),
    [
        body("text")
            .exists()
            .withMessage( error_def.INVALID_TASK_OBJECTIVE )
            .bail()
            .isString()
            .withMessage( error_def.INVALID_TASK_OBJECTIVE )
            .bail(),
        body("date")
            .optional()
            .isISO8601()
            .withMessage( error_def.INVALID_TASK_DATE )
            .toDate()
            .bail()
    ],
    async function( req, res, next ) {
        // get validation errors if any
        const errors = validationResult( req )

        // check if any validation errors and report them
        if ( !errors.isEmpty() ) {
            switch( errors.array()[0].msg ) {
                case error_def.INVALID_TASK_OBJECTIVE:
                    return reportInvalidTaskObjectiveError( next )
                
                case error_def.INVALID_TASK_DATE:
                    return reportInvalidTaskDateError( next )
            }
        }

        // get new task details from request body
        const text = req.body.text
        const date = req.body.date
        const user_id = req.user._id


        try {
            // create new task on database using new details
            const newTask = await Task.create({
                text: text,
                date: date,
                user_id: user_id
            })

            // send success response no errors were encountered
            res.status(201).json({
                status: "success",
                data: prepareTaskResponse( newTask )
            })
        } catch( err ) {
            err.errorCode = error_def.SERVER_ERROR
            return next( err )
        }
    }
)

// DELETE /api/tasks/:id - delete a task using id as created by authenticated user
router.delete("/:id",
    passport.authenticate( 'jwt', { session: false } ),
    [
        param("id")
            .exists()
            .withMessage( error_def.INVALID_REQUEST_TASK_ID )
            .bail()
            .isMongoId()
            .withMessage( error_def.INVALID_REQUEST_TASK_ID )
            .bail()
    ],
    async function( req, res, next ) {
        // get validation errors from request if any
        const errors = validationResult( req )

        // check if there are any validation errors and report them
        if ( !errors.isEmpty() ) {
            switch( errors.array()[0].msg ) {
                case error_def.INVALID_REQUEST_TASK_ID:
                    return reportInvalidRequestTaskIdError( next )
            }
        }

        try {
            // get id of task to delete from request
            const id = req.params.id

            // delete task with particular id from database
            const isTaskDeleted = await Task.where("_id").equals(id).deleteOne()

            // check if task was successfully deleted and send success response,
            // if not, send a task not found error
            if ( isTaskDeleted ) {
                res.sendStatus( 204 )
            } else {
                return reportTaskNotFoundError( next )
            }
        } catch( err ) {
            err.errorCode = error_def.SERVER_ERROR
            return next( err )
        }
    }
)

// PUT /api/tasks/:id - update a task with the request info created by authenticated user
router.put("/:id", 
    passport.authenticate("jwt", { session: false }),
    [
        param("id")
            .exists()
            .withMessage( error_def.INVALID_REQUEST_TASK_ID )
            .bail()
            .isMongoId()
            .withMessage( error_def.INVALID_REQUEST_TASK_ID )
            .bail(),
        body("text")
          .optional()
          .isString()
          .withMessage( error_def.INVALID_TASK_OBJECTIVE )
          .bail(),
        body("date")
          .optional()
          .isISO8601()
          .toDate()
          .withMessage( error_def.INVALID_TASK_DATE )
          .bail()
    ],
    async function( req, res, next ) {
        // get validation errors from request if any
        const errors = validationResult( req )

        // check if there are any validation errors and report them
        if ( !errors.isEmpty() ) {
            switch( errors.array()[0].msg ) {
                case error_def.INVALID_REQUEST_TASK_ID:
                    return reportInvalidRequestTaskIdError( next )

                case error_def.INVALID_TASK_OBJECTIVE:
                    return reportInvalidTaskObjectiveError( next )
                
                case error_def.INVALID_TASK_DATE:
                    return reportInvalidTaskDateError( next )
            }
        }


        try {
            // retrieve PUT operation info from request
            const id = req.params.id
            const updateText = req.body.text
            const updateDate = req.body.date

            // create update object to contain info for PUT operation
            // on database
            const updateObject = {}

            // check if update text is valid then add it to update object
            if ( updateText ) {
                updateObject.text = updateText
            }

            // check if update date is valid then add it to update object
            if ( updateDate ) {
                updateObject.date = updateDate
            }

            // update task using the update object and return the
            // updated object
            const updatedTask = await Task.findOneAndUpdate(
                { _id: id },
                { $set: updateObject },
                { new: true } // returns the updated document
            ).select('text date _id');

            // if update operation successful, return success response
            // else, report task-not-error
            if ( updatedTask ) {
                res.json({
                    status: "success",
                    data: updatedTask
                })
            } else {
                return reportTaskNotFoundError( next )
            }
        } catch( err ) {
            err.errorCode = error_def.SERVER_ERROR
            return next( err )
        }
    }
)

export default router