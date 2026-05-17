using System.Windows.Controls;

namespace SyslogPusher.UI.Controls;

public partial class BrandHeader : UserControl
{
    public static readonly System.Windows.DependencyProperty ProductNameProperty =
        System.Windows.DependencyProperty.Register(
            nameof(ProductName),
            typeof(string),
            typeof(BrandHeader),
            new System.Windows.PropertyMetadata(Branding.ProductName));

    public static readonly System.Windows.DependencyProperty SubtitleProperty =
        System.Windows.DependencyProperty.Register(
            nameof(Subtitle),
            typeof(string),
            typeof(BrandHeader),
            new System.Windows.PropertyMetadata(Branding.AboutText));

    public static readonly System.Windows.DependencyProperty WrittenByLineProperty =
        System.Windows.DependencyProperty.Register(
            nameof(WrittenByLine),
            typeof(string),
            typeof(BrandHeader),
            new System.Windows.PropertyMetadata(Branding.FooterLine));

    public string ProductName
    {
        get => (string)GetValue(ProductNameProperty);
        set => SetValue(ProductNameProperty, value);
    }

    public string Subtitle
    {
        get => (string)GetValue(SubtitleProperty);
        set => SetValue(SubtitleProperty, value);
    }

    public string WrittenByLine
    {
        get => (string)GetValue(WrittenByLineProperty);
        set => SetValue(WrittenByLineProperty, value);
    }

    public BrandHeader() => InitializeComponent();
}
