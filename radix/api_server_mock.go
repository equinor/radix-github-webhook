// Code generated by MockGen. DO NOT EDIT.
// Source: ./radix/api_server.go

// Package radix is a generated GoMock package.
package radix

import (
	context "context"
	reflect "reflect"

	models "github.com/equinor/radix-github-webhook/models"
	gomock "github.com/golang/mock/gomock"
)

// MockAPIServer is a mock of APIServer interface.
type MockAPIServer struct {
	ctrl     *gomock.Controller
	recorder *MockAPIServerMockRecorder
}

// MockAPIServerMockRecorder is the mock recorder for MockAPIServer.
type MockAPIServerMockRecorder struct {
	mock *MockAPIServer
}

// NewMockAPIServer creates a new mock instance.
func NewMockAPIServer(ctrl *gomock.Controller) *MockAPIServer {
	mock := &MockAPIServer{ctrl: ctrl}
	mock.recorder = &MockAPIServerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAPIServer) EXPECT() *MockAPIServerMockRecorder {
	return m.recorder
}

// GetApplication mocks base method.
func (m *MockAPIServer) GetApplication(ctx context.Context, appName string) (*models.Application, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetApplication", ctx, appName)
	ret0, _ := ret[0].(*models.Application)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetApplication indicates an expected call of GetApplication.
func (mr *MockAPIServerMockRecorder) GetApplication(ctx, appName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetApplication", reflect.TypeOf((*MockAPIServer)(nil).GetApplication), ctx, appName)
}

// ShowApplications mocks base method.
func (m *MockAPIServer) ShowApplications(ctx context.Context, sshURL string) ([]*models.ApplicationSummary, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ShowApplications", ctx, sshURL)
	ret0, _ := ret[0].([]*models.ApplicationSummary)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ShowApplications indicates an expected call of ShowApplications.
func (mr *MockAPIServerMockRecorder) ShowApplications(ctx, sshURL interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ShowApplications", reflect.TypeOf((*MockAPIServer)(nil).ShowApplications), ctx, sshURL)
}

// TriggerPipeline mocks base method.
func (m *MockAPIServer) TriggerPipeline(ctx context.Context, appName, gitRef, gitRefType, commitID, triggeredBy string) (*models.JobSummary, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "TriggerPipeline", ctx, appName, gitRef, gitRefType, commitID, triggeredBy)
	ret0, _ := ret[0].(*models.JobSummary)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// TriggerPipeline indicates an expected call of TriggerPipeline.
func (mr *MockAPIServerMockRecorder) TriggerPipeline(ctx, appName, gitRef, gitRefType, commitID, triggeredBy interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TriggerPipeline", reflect.TypeOf((*MockAPIServer)(nil).TriggerPipeline), ctx, appName, gitRef, gitRefType, commitID, triggeredBy)
}
