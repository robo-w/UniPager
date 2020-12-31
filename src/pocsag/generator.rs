use crate::message::{MessageProvider, ProtocolMessage};
use crate::pocsag::{Encoding, encoding, Message, MessageType};

/// Preamble length in number of 32-bit codewords
pub const PREAMBLE_LENGTH: u8 = 18;

const PREAMBLE_WORD: u32 = 0xAAAAAAAA;
const SYNC_WORD: u32 = 0x7CD215D8;
const IDLE_WORD: u32 = 0x7A89C197;

#[derive(Clone, Copy, Debug)]
enum State {
    Preamble,
    AddressWord,
    MessageWord(usize, Encoding),
    Completed,
}

/// POCSAG Generator
///
/// Generates 32-bit POCSAG codewords from a Message vector.
pub struct Generator<'a> {
    // Current state of the state machine
    state: State,
    // Message source
    messages: &'a mut (dyn MessageProvider + 'a),
    // Current message being sent
    message: Option<Message>,
    // Number of codewords left in current batch
    codewords: u8,
    // Number of codewords generated
    count: usize,
}

impl<'a> Generator<'a> {
    /// Create a new Generator
    pub fn new(messages: &'a mut dyn MessageProvider, first_msg: Message)
               -> Generator<'a> {
        Generator {
            state: State::Preamble,
            messages,
            message: Some(first_msg),
            codewords: PREAMBLE_LENGTH,
            count: 0,
        }
    }

    // Get the next message and return the matching state.
    fn next_message(&mut self) -> State {
        let message = self.messages.next(self.count - 1).map(|msg| msg.message);
        self.message = match message {
            Some(ProtocolMessage::Pocsag(pocsag_message)) => Some(pocsag_message),
            _ => None
        };

        match self.message
        {
            Some(_) => State::AddressWord,
            None => State::Completed,
        }
    }
}

// Calculate the CRC for a codeword and return the updated codeword.
fn crc(codeword: u32) -> u32 {
    let mut crc = codeword;
    for i in 0..=21 {
        if (crc & (0x80000000 >> i)) != 0 {
            crc ^= 0xED200000 >> i;
        }
    }
    codeword | crc
}

// Calculate the parity bit for a codeword and return the updated codeword.
fn parity(codeword: u32) -> u32 {
    let mut parity = codeword ^ (codeword >> 1);
    parity ^= parity >> 2;
    parity ^= parity >> 4;
    parity ^= parity >> 8;
    parity ^= parity >> 16;
    codeword | (parity & 1)
}

impl<'a> Iterator for Generator<'a> {
    // The Iterator returns 32-bit codewords.
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        trace!(
            "Generating next 32 bit codeword for state: codewords_left={}, state={:?}, codewords_generated={}",
            self.codewords,
            self.state,
            self.count);
        self.count += 1;

        match (self.codewords, self.state)
        {
            (0, State::Completed) => {
                trace!("  Generator completed and no codewords left. Stopping generator.");
                None
            }

            (0, State::Preamble) => {
                trace!("  Preamble completed. Sending SYNC word and starting new batch of 16 codewords.");
                self.codewords = 16;
                self.state = State::AddressWord;
                Some(SYNC_WORD)
            }

            (0, _) => {
                trace!("  No codewords left in current batch. Sending SYNC word and starting a new batch with 16 codewords.");
                self.codewords = 16;
                Some(SYNC_WORD)
            }

            (_, State::Preamble) => {
                trace!("  Sending PREAMBLE codeword. Preamble codewords left: {}", self.codewords);
                self.codewords -= 1;
                Some(PREAMBLE_WORD)
            }

            // Send the address word for the current message
            (codeword, State::AddressWord) => {
                let length =
                    self.message.as_ref().map(|m| m.data.len()).unwrap_or(0);

                let &Message { ric, func, mtype, .. } =
                    self.message.as_ref().unwrap();
                trace!(
                    "  Sending ADDRESS word for current message: RIC=0x{:X}, function=0x{:X}, message_type={:?}",
                    ric,
                    func,
                    mtype);

                self.codewords -= 1;

                // Send idle words until the current batch position
                // matches the position required by the subric.
                if ((ric & 0b111) << 1) as u8 == 16 - codeword {
                    // Set the next state according to the message type
                    self.state = if length == 0 {
                        trace!("  Empty length. Calculating state based on next message.");
                        self.next_message()
                    } else {
                        trace!("  Message with length > 0. Calculating state based on message type.");
                        match mtype
                        {
                            MessageType::Numeric => {
                                State::MessageWord(0, encoding::NUMERIC)
                            }
                            MessageType::AlphaNum => {
                                State::MessageWord(0, encoding::ALPHANUM)
                            }
                        }
                    };

                    // Encode the address word.
                    let addr = (ric & 0x001ffff8) << 10;
                    let func = (func as u32 & 0b11) << 11;
                    let address_word = parity(crc(addr | func));
                    trace!(
                        "  Writing address word for current message. raw: 0x{:X}, with CRC and parity: 0x{:X}",
                        addr | func,
                        address_word);
                    Some(address_word)
                } else {
                    trace!("  Position does not match. Sending IDLE word.");
                    Some(IDLE_WORD)
                }
            }

            // Send the next message word of the current message.
            (_, State::MessageWord(pos, encoding)) => {
                trace!("  Sending MESSAGE codeword. Codewords left: {}", self.codewords);
                self.codewords -= 1;
                let mut pos = pos;
                let mut codeword: u32 = 0;

                let completed = {
                    let message = self.message.as_ref().unwrap();
                    let mut bytes = message.data.bytes();

                    // Get the next symbol and shift it to start with correct
                    // bit.
                    let mut sym = bytes
                        .nth(pos / encoding.bits)
                        .map(encoding.encode)
                        .unwrap_or(encoding.trailing) >>
                        (pos % encoding.bits);

                    for _ in 0..20 {
                        // Add the next bit of the symbol to the codeword.
                        codeword = (codeword << 1) | (sym & 1) as u32;

                        pos += 1;

                        // If all bits are sent, continue with the next symbol.
                        if pos % encoding.bits == 0 {
                            sym = bytes.next().map(encoding.encode).unwrap_or(
                                encoding.trailing
                            );
                        } else {
                            sym >>= 1;
                        }
                    }

                    // If no symbols are left, the message is completed.
                    pos > message.data.len() * encoding.bits
                };

                // Continue with the next message if the current one is
                // completed.
                self.state = if completed {
                    self.next_message()
                } else {
                    State::MessageWord(pos, encoding)
                };

                // TODO: ensure that an trailing IDLE, SYNC or ADDR word is sent

                let message_word = parity(crc(0x80000000 | (codeword << 11)));
                trace!("  Writing message codeword. raw: 0x{:X}, with CRC and parity: {:X}", codeword, message_word);
                Some(message_word)
            }

            (_, State::Completed) => {
                trace!("  Sending IDLE codewords to fill remaining batch until complete. Codewords left: {}", self.codewords);
                self.codewords -= 1;
                Some(IDLE_WORD)
            }
        }
    }
}
