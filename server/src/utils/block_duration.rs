use std::time::Duration;

/// Average time between bitcoin blocks
const BLOCK_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Convert a duration to an estimated number of blocks, rounding up
pub fn duration_to_blocks(duration: Duration) -> u32 {
	duration.as_secs().div_ceil(BLOCK_INTERVAL.as_secs()) as u32
}

/// Convert a number of blocks to an estimated duration
pub fn blocks_to_duration(blocks: u32) -> Duration {
	BLOCK_INTERVAL * blocks
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn one_day() {
		let day = Duration::from_secs(24 * 60 * 60);
		assert_eq!(duration_to_blocks(day), 144);
		assert_eq!(blocks_to_duration(144), day);
	}

	#[test]
	fn one_hour() {
		let hour = Duration::from_secs(60 * 60);
		assert_eq!(duration_to_blocks(hour), 6);
		assert_eq!(blocks_to_duration(6), hour);
	}

	#[test]
	fn zero() {
		assert_eq!(duration_to_blocks(Duration::ZERO), 0);
		assert_eq!(blocks_to_duration(0), Duration::ZERO);
	}

	#[test]
	fn rounds_up() {
		// 9 minutes < 10 minute block interval, rounds up to 1
		let nine_min = Duration::from_secs(9 * 60);
		assert_eq!(duration_to_blocks(nine_min), 1);
	}

}
