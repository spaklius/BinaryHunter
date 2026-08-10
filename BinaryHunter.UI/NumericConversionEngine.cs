using System.Globalization;

namespace BinaryHunter.UI;

public sealed record NumericConversionProfile(double Factor, double Offset, string Formula, string Unit)
{
    public static NumericConversionProfile Default { get; } = new(1d, 0d, "x", string.Empty);
    public bool IsIdentity => Math.Abs(Factor - 1d) < 1e-12 && Math.Abs(Offset) < 1e-12 &&
                              (string.IsNullOrWhiteSpace(Formula) || Formula.Trim().Equals("x", StringComparison.OrdinalIgnoreCase));

    public double Convert(double raw) => NumericFormula.Evaluate(Formula, raw) * Factor + Offset;
}

public static class NumericFormula
{
    public static double Evaluate(string? expression, double x)
    {
        if (string.IsNullOrWhiteSpace(expression)) return x;
        var parser = new Parser(expression, x);
        var result = parser.ParseExpression();
        parser.SkipWhiteSpace();
        if (!parser.AtEnd) throw new FormatException($"Unexpected token at position {parser.Position + 1}.");
        if (!double.IsFinite(result)) throw new FormatException("The formula result is not a finite number.");
        return result;
    }

    public static bool TryEvaluate(string? expression, double x, out double result, out string error)
    {
        try
        {
            result = Evaluate(expression, x);
            error = string.Empty;
            return true;
        }
        catch (Exception exception) when (exception is FormatException or OverflowException or DivideByZeroException)
        {
            result = 0;
            error = exception.Message;
            return false;
        }
    }

    private sealed class Parser(string text, double x)
    {
        private int _position;
        public int Position => _position;
        public bool AtEnd => _position >= text.Length;

        public double ParseExpression()
        {
            var value = ParseTerm();
            while (true)
            {
                SkipWhiteSpace();
                if (Match('+')) value += ParseTerm();
                else if (Match('-')) value -= ParseTerm();
                else return value;
            }
        }

        private double ParseTerm()
        {
            var value = ParsePower();
            while (true)
            {
                SkipWhiteSpace();
                if (Match('*')) value *= ParsePower();
                else if (Match('/')) value /= ParsePower();
                else if (Match('%')) value %= ParsePower();
                else return value;
            }
        }

        private double ParsePower()
        {
            var value = ParseUnary();
            SkipWhiteSpace();
            return Match('^') ? Math.Pow(value, ParsePower()) : value;
        }

        private double ParseUnary()
        {
            SkipWhiteSpace();
            if (Match('+')) return ParseUnary();
            if (Match('-')) return -ParseUnary();
            return ParsePrimary();
        }

        private double ParsePrimary()
        {
            SkipWhiteSpace();
            if (Match('('))
            {
                var value = ParseExpression();
                SkipWhiteSpace();
                if (!Match(')')) throw new FormatException("A closing parenthesis is missing.");
                return value;
            }

            if (!AtEnd && (char.IsDigit(text[_position]) || text[_position] == '.'))
                return ParseNumber();
            if (!AtEnd && (char.IsLetter(text[_position]) || text[_position] == '_'))
            {
                var identifier = ParseIdentifier();
                if (identifier.Equals("x", StringComparison.OrdinalIgnoreCase)) return x;
                if (identifier.Equals("pi", StringComparison.OrdinalIgnoreCase)) return Math.PI;
                if (identifier.Equals("e", StringComparison.OrdinalIgnoreCase)) return Math.E;
                SkipWhiteSpace();
                if (!Match('(')) throw new FormatException($"Unknown identifier '{identifier}'.");
                var arguments = new List<double>();
                SkipWhiteSpace();
                if (!Match(')'))
                {
                    do
                    {
                        arguments.Add(ParseExpression());
                        SkipWhiteSpace();
                    } while (Match(','));
                    if (!Match(')')) throw new FormatException("A function closing parenthesis is missing.");
                }
                return EvaluateFunction(identifier, arguments);
            }
            throw new FormatException($"A number, x, or '(' was expected at position {_position + 1}.");
        }

        private double ParseNumber()
        {
            var start = _position;
            while (!AtEnd)
            {
                var current = text[_position];
                if (char.IsDigit(current) || current is '.' or 'e' or 'E')
                {
                    _position++;
                    continue;
                }
                if (current is '+' or '-' && _position > start && text[_position - 1] is 'e' or 'E')
                {
                    _position++;
                    continue;
                }
                break;
            }
            if (!double.TryParse(text.AsSpan(start, _position - start), NumberStyles.Float,
                    CultureInfo.InvariantCulture, out var value))
                throw new FormatException($"Invalid number at position {start + 1}.");
            return value;
        }

        private string ParseIdentifier()
        {
            var start = _position;
            while (!AtEnd && (char.IsLetterOrDigit(text[_position]) || text[_position] == '_')) _position++;
            return text[start.._position];
        }

        private static double EvaluateFunction(string name, IReadOnlyList<double> args)
        {
            static void Count(string function, IReadOnlyList<double> values, int expected)
            {
                if (values.Count != expected)
                    throw new FormatException($"{function} expects {expected} argument(s).");
            }
            var key = name.ToLowerInvariant();
            return key switch
            {
                "abs" => One(Math.Abs), "sqrt" => One(Math.Sqrt), "ln" => One(Math.Log),
                "log" => One(Math.Log10), "exp" => One(Math.Exp), "floor" => One(Math.Floor),
                "ceil" => One(Math.Ceiling), "round" => One(Math.Round),
                "min" => Two(Math.Min), "max" => Two(Math.Max), "pow" => Two(Math.Pow),
                _ => throw new FormatException($"Unknown function '{name}'.")
            };

            double One(Func<double, double> function)
            {
                Count(name, args, 1);
                return function(args[0]);
            }
            double Two(Func<double, double, double> function)
            {
                Count(name, args, 2);
                return function(args[0], args[1]);
            }
        }

        public void SkipWhiteSpace()
        {
            while (!AtEnd && char.IsWhiteSpace(text[_position])) _position++;
        }

        private bool Match(char expected)
        {
            if (AtEnd || text[_position] != expected) return false;
            _position++;
            return true;
        }
    }
}
