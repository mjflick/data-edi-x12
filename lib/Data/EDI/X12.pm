package Data::EDI::X12;
use strict;

use YAML qw(LoadFile Load);
use IO::File;

our $VERSION = '0.01';

=head1 NAME

Data::EDI::X12 - EDI X12 Processing for Perl

=cut

=head1 SYNOPSIS

 my $x12 = Data::EDI::X12->new({ spec_file => 'edi.yaml', new_lines => 1, truncate_null => 1 });
 my $data = $x12->read_record(...);
 print $x12->write_record($data);


=head1 METHODS

=cut

sub debug { shift->{debug} }

my $DEFAULT_CONFIG = {
    ISA => {
        definition => [
            {
                type => 'text',
                name => 'authorization_information_qualifier',
                value => '00',
                bytes => 2,
            },
            {
                type => 'filler',
                bytes => 10,
                value => ' ',
            },
            {
                type => 'text',
                name => 'security_information_qualifier',
                value => '00',
                bytes => 2,
            },
            {
                type => 'filler',
                bytes => 10,
                value => ' ',
            },
            {
                type => 'text',
                name => 'interchange_id_qualifier_1',
                value => '00',
                bytes => 2,
            },
            {
                type => 'text',
                name => 'interchange_id_1',
                value => '00',
                bytes => 15,
            },
            {
                type => 'text',
                name => 'interchange_id_qualifier_2',
                value => '00',
                bytes => 2,
            },
            {
                type => 'text',
                name => 'interchange_id_2',
                value => '00',
                bytes => 15,
            },
            {
                type => 'text',
                name => 'date',
                value => '',
                bytes => 6,
            },
            {
                type => 'text',
                name => 'time',
                value => '',
                bytes => 4,
            },
            {
                type => 'text',
                name => 'repetition_separator',
                value => 'U',
                bytes => 1,
            },
            {
                type => 'text',
                name => 'control_version_number',
                bytes => 5,
            },
            {
                type => 'text',
                name => 'control_number',
                bytes => 9,
                format => '%09i',
            },
            {
                type => 'text',
                name => 'acknowledgment_requested',
                bytes => 1,
            },
            {
                type => 'text',
                name => 'usage_indicator',
                bytes => 1,
                value => 'P',
            },
            {
                type => 'text',
                bytes => 1,
                value => '>',
            }
        ],
    },
    IEA => {
        definition => [
            {
                name => 'total',
                min => 1,
                max => 10,
            },
            {
                name => 'control_number',
                min => 4,
                max => 9,
                format => '%09i',
            },
        ],
    },
    GS => {
        definition => [
            {
                type => 'text',
                name => 'type',
                value => '00',
                bytes => 2,
            },
            {
                type => 'text',
                name => 'sender_code',
                bytes => 9,
            },
            {
                type => 'text',
                name => 'receiver_code',
                bytes => 9,
            },
            {
                type => 'text',
                name => 'date',
                value => '',
                bytes => 8,
            },
            {
                type => 'text',
                name => 'time',
                value => '',
                bytes => 4,
            },
            {
                type => 'text',
                name => 'control_number',
                bytes => 9,
                format => '%09i',
            },
            {
                type => 'text',
                name => 'agency_code',
                bytes => 1,
                value => 'X',
            },
            {
                type => 'text',
                name => 'version_number',
                bytes => 6,
            },
        ],
    },
    ST => {
        definition => [
            {
                name => 'identifier_code',
                min => 3,
                max => 3,
            },
            {
                name => 'control_number',
                min => 4,
                max => 9,
                format => '%04i',
            },
        ],
    },
    SE => {
        definition => [
            {
                name => 'total',
                min => 1,
                max => 10,
            },
            {
                name => 'control_number',
                min => 4,
                max => 9,
                format => '%04i',
            },
        ],
    },
    GE => {
        definition => [
            {
                name => 'total',
                min => 1,
                max => 10,
            },
            {
                name => 'control_number',
                min => 4,
                max => 9,
                format => '%09i',
            },
        ],
    },
};

=head2 new

 my $x12 = Data::EDI::X12->new({ spec_file => 'edi.yaml', new_lines => 1, truncate_null => 1 });

=cut

sub new
{
    my ($class, $args) = @_;

    my $yaml_spec;
    if ($args->{spec})
    {
        $yaml_spec = Load($args->{spec});
    }
    elsif ($args->{spec_file})
    {
        $yaml_spec = LoadFile($args->{spec_file});
    }
    else
    {
        die sprintf("[%s] args spec or spec_file must be specified", __PACKAGE__);
    }

    my $spec = {
        %$DEFAULT_CONFIG,
        %$yaml_spec,
    };

    my $self = {
        spec       => $spec,
        debug      => $args->{debug},
        terminator => $args->{terminator} || '~',        
        separator  => $args->{separator}  || '*',
        error      => '',
        new_lines  => $args->{new_lines},
        truncate_null => $args->{truncate_null} || 0,
    };
    bless($self);

    return $self;
}

=head2 read_record

 my $record = $x12->read_record($string);

=cut

sub read_record
{
    my ($self, $string) = @_;

    my $record = { };

    # strip newlines if applicable
    $string =~ s/[\r\n]//g;

    open(my $fh, "<", \$string);

    #$self->_parse_transaction_set({
    $self->_parse_edi({
        fh         => $fh,
        string     => $string,
        record     => $record,
    });
        
    return $record;
}

=head3 write_record

 my $string = $x12->write_record($record);

=cut

sub write_record
{
    my ($self, $record) = @_;

    my $string = '';
    open(my $fh, ">", \$string);
    $self->_write_edi({
        fh         => $fh,
        string     => $string,
        record     => $record,
    });
        
    return $string;
}

sub _split_string
{
    my ($self, $string) = @_;
    my $term_val = quotemeta($self->{terminator});
    my $sep_val  = quotemeta($self->{separator});

    my @records;
    push @records, [ split(/$sep_val/, $_) ]
        for split(/$term_val/, $string);

    return @records;
}

sub _parse_definition
{
    my ($self, $params) = @_;

    my $record = { };

    my $definition     = $params->{definition};

    my $segments       = $params->{segments};
    my $type           = $params->{type};

    for my $def (@{ $definition || [ ] })
    {
        my $segment = shift(@$segments);
        $segment =~ s/\s+$//g;
                
        $record->{$def->{name}} = $segment
            if $def->{name};
    }

    return $record;
}

sub _parse_edi
{
    my ($self, $params) = @_;

    my $fh             = $params->{fh};
    my $record         = $params->{record};
    my $definition     = $params->{definition};
    my $string         = $params->{string};

    my $IN_ISA = 0;
    my $IN_GS = 0;
    my $IN_ST = 0;

    my ($current_group, $current_set, $current_record);

    $record->{GROUPS} = [ ]
        unless exists $record->{GROUPS};

    for my $segments ($self->_split_string($string))
    {
        my $type = uc(shift(@$segments));

        if ($type eq 'ISA')
        {
            $record->{ISA} = $self->_parse_definition({
                definition => $self->{spec}->{ISA}->{definition},
                segments   => $segments,
                type       => $type,
            });

            $IN_ISA = 1;
        }
        elsif ($type eq 'IEA')
        {
            $IN_ISA = 0;
        }
        elsif ($type eq 'GS')
        {
            my $new_group = $self->_parse_definition({
                definition => $self->{spec}->{GS}->{definition},
                segments   => $segments,
                type       => $type,
            });

            $new_group->{SETS} = [ ];

            $IN_GS = 1;

            $current_group = $new_group;
        }
        elsif ($type eq 'GE')
        {
            push @{ $record->{GROUPS} }, \%$current_group;

            $IN_GS = 0;
        }
        elsif ($type eq 'ST')
        {
            my $new_set = $self->_parse_definition({
                definition => $self->{spec}->{ST}->{definition},
                segments   => $segments,
                type       => $type,
            });

            $IN_ST = 1;

            $current_set = $new_set;
            $current_record = $new_set;
        }
        elsif ($type eq 'SE')
        {
            push @{ $current_group->{SETS} }, \%$current_set;

            $IN_GS = 0;
        }
        else
        {
            my $doc_id = $current_set->{identifier_code};
            my $spec   = $self->{spec}->{$doc_id};

            # parse a record
            my %segment_to_section;
            for my $section (keys %{ $spec->{structure} || [ ] })
            {
                for my $segment (@{ $spec->{structure}{$section} || [ ] })
                {
                    $segment_to_section{$segment} = uc($section);
                }
            }

            my $section  = $segment_to_section{$type};
            my $mod_record;

            if (my $type_def = $spec->{segments}{uc($type)})
            {
                if ($section eq 'DETAIL')
                {
                    $current_record->{DETAIL} = [{}]
                        unless exists $current_record->{DETAIL};

                    push @{ $current_record->{DETAIL} }, {}
                        if exists($current_record->{DETAIL}->[-1]->{$type});

                    $current_record->{DETAIL}->[-1]->{$type} = $self->_parse_definition({
                        definition => $type_def->{definition},
                        segments   => $segments,
                        type       => $type,
                    });
                }
                else
                {
                    $current_record->{$section} = {}
                        unless exists $current_record->{$section};

                    $current_record->{$section}->{$type} = $self->_parse_definition({
                        definition => $type_def->{definition},
                        segments   => $segments,
                        type       => $type,
                    });
                }
            }
        }
    }
}

sub _parse_transaction_set
{
    my ($self, $params) = @_;

    my $fh             = $params->{fh};
    my $record         = $params->{record};
    my $definition     = $params->{definition};
    my $string         = $params->{string};
    my $rows           = $params->{rows};

    my $buffer = '';

    my %segment_to_section;
    for my $section (keys %{ $self->{spec}{structure} || [ ] })
    {
        for my $segment (@{ $self->{spec}{structure}{$section} || [ ] })
        {
            $segment_to_section{$segment} = $section;
        }
    }

    for my $segments (@{ $rows })
    {
        my $type     = shift(@$segments);
        my $section  = $segment_to_section{$type};
        my $mod_record;

        if (my $type_def = $self->{spec}->{segments}{uc($type)})
        {
            if ($section eq 'detail')
            {
                $record->{detail} = [{}]
                    unless exists $record->{detail};

                $mod_record = $record->{detail}->[-1];

                if (exists($mod_record->{$type}))
                {
                    push @{ $record->{detail} }, {};
                    $mod_record = $record->{detail}->[-1];
                }
            }
            else
            {
                $record->{$section} = {}
                    unless exists $record->{$section};

                $mod_record = $record->{$section};
            }

            $self->_parse_definition({
                record     => $mod_record,
                definition => $type_def->{definition},
                segments   => $segments,
                type       => $type,
            });
        }
        else
        {
            die __PACKAGE__ . ": `$type` not supported";
        }

    }
}

sub _write_spec
{
    my ($self, %params) = @_;
    my $type_def = $params{type_def};
    my $record   = $params{record};
    my @line     = ($params{type});
    my $term_val = $self->{terminator};
    my $sep_val  = $self->{separator};

    for my $def (@{ $type_def->{definition} || [ ] })
    {
        my $value = ($def->{name} and exists($record->{$def->{name}})) ?
            $record->{$def->{name}} : $def->{value};

        $value = '' unless defined $value;

        $def->{bytes} ||= '';

        # deal with minimum
        $def->{bytes} = $def->{min}
            if $value ne '' and not($def->{bytes}) and $def->{min} and length($value) < $def->{min};

        $def->{bytes} = '-' . $def->{bytes}
            if $def->{bytes};

        my $format = $def->{format} || "\%$def->{bytes}s";
                
        # deal with maximum limits
        $value = substr($value, 0, $def->{max})
            if $def->{max};

        push @line, sprintf($format, $value);
    }

    
    if ($self->{truncate_null})
    {
        for my $val (reverse @line)
        {
            last if $val ne '';

            pop(@line);
        }
    }    
    
    my $string = join($sep_val, @line);
    $string   .= $term_val;
    $string   .= "\n" if $self->{new_lines};

    return $string;
}

sub _write_edi
{
    my ($self, $params) = @_;

    my $fh             = $params->{fh};
    my $record         = $params->{record};
    my $definition     = $params->{definition};
    my $string         = $params->{string};

    my $buffer = '';

    my $term_val = $self->{terminator};
    my $sep_val  = $self->{separator};

    $record->{ISA}{control_number} = 1
        unless exists $record->{ISA}{control_number};

    # write ISA header
    print $fh $self->_write_spec(
        type     => 'ISA',
        type_def => $self->{spec}->{ISA},
        record   => $record->{ISA},
    );

    my $group_count = 0;
    # iterate through document structure
    for my $group (@{ $record->{GROUPS} || [ ] })
    {
        $group_count++;

        $group->{control_number} = $group_count unless exists $group->{control_number};

        # process GS line
        print $fh $self->_write_spec(
            type     => 'GS',
            type_def => $self->{spec}->{GS},
            record   => $group,
        );

        my $set_count = 0;

        for my $set (@{ $group->{SETS} || [ ] })
        {
            my $record_count = 2;

            $set_count++;

            $set->{control_number} = $set_count
                unless exists $set->{control_number};

            # process ST line
            print $fh $self->_write_spec(
                type     => 'ST',
                type_def => $self->{spec}->{ST},
                record   => $set,
            );

            ######
            # process actual set
            my $doc_id = $set->{identifier_code};
            my $spec   = $self->{spec}->{$doc_id};

            die "cannot find spec for $doc_id"
                unless $spec;

            # process set header
            for my $section (@{ $spec->{structure}{header} || [ ] })
            {
                $record_count++;
                print $fh $self->_write_spec(
                    type     => $section,
                    type_def => $spec->{segments}{$section},
                    record   => $set->{HEADER}{$section},
                );
            }

            # process set details
            for my $detail (@{ $set->{DETAIL} || [ ] })
            {
                for my $section (@{ $spec->{structure}{detail} || [ ] })
                {
                    $record_count++;
                    print $fh $self->_write_spec(
                        type     => $section,
                        type_def => $spec->{segments}{$section},
                        record   => $detail->{$section},
                    );
                }
            }
            

            # process set footer
            for my $section (@{ $spec->{structure}{footer} || [ ] })
            {
                $record_count++;
                print $fh $self->_write_spec(
                    type     => $section,
                    type_def => $spec->{segments}{$section},
                    record   => $set->{FOOTER}{$section},
                );
            }

            ######

            # process SE line
            $record_count++;
            print $fh $self->_write_spec(
                type     => 'SE',
                type_def => $self->{spec}->{SE},
                record   => {
                    total          => $record_count,
                    control_number => $set->{control_number},
                },
            );

            
        }

        # process GE line
        print $fh $self->_write_spec(
            type     => 'GE',
            type_def => $self->{spec}->{GE},
            record   => {
                control_number => $group->{control_number},
                total          => $set_count,
            },
        );
    }

    # write IEA header
    print $fh $self->_write_spec(
        type     => 'IEA',
        type_def => $self->{spec}->{IEA},
        record   => {
            control_number => $record->{ISA}{control_number},
            total          => $group_count,
        },
    );
    
    # write details
    for my $detail ( @{ $record->{detail} || [ ] } )
    {
        for my $section (@{ $self->{spec}{structure}{detail} || [ ] })
        {
            if (my $type_def = $self->{spec}->{segments}{uc($section)})
            {
                my @line = ($section);

                for my $def (@{ $type_def->{definition} || [ ] })
                {
                    my $value = exists $detail->{$section}{$def->{name}} ?
                        $detail->{$section}{$def->{name}} :
                        $def->{value};

                    $def->{bytes} ||= '';

                    # deal with minimum
                    $def->{bytes} = $def->{min}
                        if $value ne '' and not($def->{bytes}) and $def->{min} and length($value) < $def->{min};

                    $def->{bytes} = '-' . $def->{bytes}
                        if $def->{bytes};

                    my $format = $def->{format} || "\%$def->{bytes}s";

                    # deal with maximum limits
                    $value = substr($value, 0, $def->{max})
                        if $def->{max};

                    push @line, sprintf($format, $value);
                }

                print $fh join($sep_val, @line);
                print $fh $term_val;
                print $fh "\n" if $self->{new_lines};
            }
        }
    }

    # write footer
    for my $section (@{ $self->{spec}{structure}{footer} || [ ] })
    {
        if (my $type_def = $self->{spec}->{segments}{uc($section)})
        {
            my @line = ($section);

            for my $def (@{ $type_def->{definition} || [ ] })
            {
                my $value = exists $record->{footer}{$section}{$def->{name}} ?
                    $record->{footer}{$section}{$def->{name}} :
                    $def->{value};

                $def->{bytes} ||= '';

                # deal with minimum
                $def->{bytes} = $def->{min}
                    if $value ne '' and not($def->{bytes}) and $def->{min} and length($value) < $def->{min};

                $def->{bytes} = '-' . $def->{bytes}
                    if $def->{bytes};

                my $format = $def->{format} || "\%$def->{bytes}s";

                # deal with maximum limits
                $value = substr($value, 0, $def->{max})
                    if $def->{max};

                push @line, sprintf($format, $value);
            }

            print $fh join($sep_val, @line);
            print $fh $term_val;
            print $fh "\n" if $self->{new_lines};
        }
    }
}

=head1 AUTHOR

Bizowie (L<http://bizowie.com>)

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2014 Bizowie

This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself, either Perl version 5.14.2 or, at your option, any later version of Perl 5 you may have available.

=cut

1;
