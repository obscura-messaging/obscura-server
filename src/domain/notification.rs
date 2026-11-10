use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceEvent {
    MessageReceived = 1,
    Disconnect = 2,
}

#[derive(Debug, Clone)]
pub struct RealtimeNotification {
    pub device_id: Uuid,
    pub event: DeviceEvent,
}

impl TryFrom<u8> for DeviceEvent {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::MessageReceived),
            2 => Ok(Self::Disconnect),
            _ => Err(()),
        }
    }
}
