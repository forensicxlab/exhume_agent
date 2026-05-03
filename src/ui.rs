use tokio::sync::{mpsc, oneshot};

#[derive(Clone)]
pub struct UiHandle {
    tx: mpsc::UnboundedSender<UiEvent>,
}

pub struct ApprovalRequest {
    pub prompt: String,
    pub responder: oneshot::Sender<bool>,
}

pub enum UiEvent {
    Log(String),
    ApprovalRequest(ApprovalRequest),
    ReportUpdated,
}

impl UiHandle {
    pub fn channel() -> (Self, mpsc::UnboundedReceiver<UiEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx }, rx)
    }

    pub fn log<S: Into<String>>(&self, message: S) {
        let _ = self.tx.send(UiEvent::Log(message.into()));
    }

    pub async fn request_approval<S: Into<String>>(&self, prompt: S) -> bool {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(UiEvent::ApprovalRequest(ApprovalRequest {
                prompt: prompt.into(),
                responder: tx,
            }))
            .is_err()
        {
            return false;
        }
        rx.await.unwrap_or(false)
    }

    pub fn report_updated(&self) {
        let _ = self.tx.send(UiEvent::ReportUpdated);
    }
}
