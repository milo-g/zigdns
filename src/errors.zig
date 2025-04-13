pub const ParseError = error{
    InvalidHeaderLength,
    InvalidLabelLength,
    InvalidTotalLength,
    EndOfStream,
};
