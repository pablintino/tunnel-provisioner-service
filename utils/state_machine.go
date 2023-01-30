package utils

import (
	"errors"
	"sync"
)

// Took from https://venilnoronha.io/a-simple-state-machine-framework-in-go

// ErrEventRejected is the error returned when the state machine cannot process
// an event in the state that it is in.
var ErrEventRejected = errors.New("event rejected")

const (
	// NoOp represents a no-op event.
	NoOp EventType = "NoOp"
)

// StateType represents an extensible state type in the state machine.
type StateType string

// EventType represents an extensible event type in the state machine.
type EventType string

// EventContext represents the context to be passed to the action implementation.
type EventContext interface{}

// Action represents the action to be executed in a given state.
type Action interface {
	Execute(eventCtx EventContext) EventType
}

type FSMTransition struct {
	Target StateType
	Action Action
}

// State binds a state with an action and a set of events it can handle.
type FSMEventTransitions map[EventType]FSMTransition

// States represents a mapping of states and their implementations.
type Transitions map[StateType]FSMEventTransitions

// StateMachine represents the state machine.
type StateMachine struct {
	// Previous represents the previous state.
	Previous StateType

	// Current represents the current state.
	Current StateType

	// States holds the configuration of states and events handled by the state machine.
	Transitions Transitions

	// mutex ensures that only 1 event is processed by the state machine at any given time.
	mutex sync.Mutex
}

func (s *StateMachine) getStateTransition(event EventType) (*FSMTransition, error) {
	if transition, ok := s.Transitions[s.Current][event]; ok {
		return &transition, nil
	}
	return nil, ErrEventRejected
}

// SendEvent sends an event to the state machine.
func (s *StateMachine) SendEvent(event EventType, eventCtx EventContext) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for {
		// Determine the next state for the event given the machine's current state.
		transition, err := s.getStateTransition(event)
		if err != nil {
			return err
		}

		// Transition over to the next state.
		s.Previous = s.Current
		s.Current = transition.Target

		// Execute the next state's action and loop over again if the event returned
		// is not a no-op.
		nextEvent := transition.Action.Execute(eventCtx)
		if nextEvent == NoOp {
			return nil
		}
		event = nextEvent

	}
}
