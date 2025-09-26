function notFound( req, res, next ) {
    const routeNotFoundError = new Error('Route not found')
    routeNotFoundError.statusCode = 404
    routeNotFoundError.errorCode = "invalid_api_route"
    next( routeNotFoundError )
}

export default notFound