use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UserEvent {
    MessageReceived = 1,
    Disconnect = 2,
    PreKeyLow = 3,
    LinkApproved = 4,
}

#[derive(Debug, Clone)]
pub struct RealtimeNotification {
    pub device_id: Uuid,
    pub event: UserEvent,
}

impl TryFrom<u8> for UserEvent {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::MessageReceived),
            2 => Ok(Self::Disconnect),
            3 => Ok(Self::PreKeyLow),
            4 => Ok(Self::LinkApproved),
            _ => Err(()),
        }
    }
}
