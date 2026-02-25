/// Unique identifier for panes
pub type PaneId = u32;

/// Unique identifier for splits
pub type SplitId = u32;

/// Split orientation
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Orientation {
    Horizontal,
    Vertical,
}

/// A node in the layout tree - either a leaf pane or a nested split
#[derive(Debug, Clone)]
pub enum LayoutNode {
    Pane(PaneId),
    Split(SplitId),
}

/// A split between two layout nodes
#[derive(Debug)]
pub struct Split {
    pub id: SplitId,
    pub orientation: Orientation,
    /// Ratio of first child (0.0 to 1.0)
    pub ratio: f64,
    pub first: LayoutNode,
    pub second: LayoutNode,
}
