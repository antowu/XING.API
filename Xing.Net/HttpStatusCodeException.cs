using System;
using System.Net;

namespace Xing
{
    /// <summary>
    /// Exception that is thrown when the server returns a HTTP status code other than 200.
    /// </summary>
    [Serializable]
    public class HttpStatusCodeException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HttpStatusCodeException"/> class.
        /// </summary>
        /// <param name="statusCode">The status code returned by the server.</param>
        public HttpStatusCodeException(HttpStatusCode statusCode)
            : this(statusCode, null)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RequestAbortedException"/> class with a
        /// reference to the inner exception that is the cause of this exception.</summary>
        /// <param name="innerException">The exception that is the cause of the current exception,
        /// or a <c>null</c> reference if no inner exception is specified.</param>
        /// <param name="statusCode">The status code returned by the server.</param>
        public HttpStatusCodeException(HttpStatusCode statusCode, Exception innerException)
            : this(statusCode, string.Format("The server returned a {0} ({1}) status code.", (int)statusCode, statusCode), innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RequestAbortedException"/> class with a
        /// specified error message and a reference to the inner exception that is the cause
        /// of this exception.</summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="innerException">The exception that is the cause of the current exception,
        /// or a <c>null</c> reference if no inner exception is specified.</param>
        /// <param name="statusCode">The status code returned by the server.</param>
        public HttpStatusCodeException(HttpStatusCode statusCode, string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>
        /// Gets or sets the HTTP status code that was returned by the server,
        /// </summary>
        public HttpStatusCode StatusCode { get; set; }
    }
}
