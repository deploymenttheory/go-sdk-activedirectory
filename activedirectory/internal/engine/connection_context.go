package engine

import (
	"context"
	"fmt"
	"time"
)

// InternalConnectionContextCause preserves an observed caller cause, including
// custom cancellation. A socket deadline may fire before the context timer is
// scheduled; an elapsed bounded deadline still establishes DeadlineExceeded.
// This does not decide whether a request was submitted, accepted or rejected.
// Workflows must retain those observations before joining the context cause.
func InternalConnectionContextCause(ctx context.Context) error {
	if cause := context.Cause(ctx); cause != nil {
		return fmt.Errorf("directory connection context ended: %w", cause)
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}
